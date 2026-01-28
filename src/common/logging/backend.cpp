// SPDX-FileCopyrightText: Copyright 2014 Citra Emulator Project
// SPDX-FileCopyrightText: Copyright 2026 shadPS4 Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <thread>
#include <vector>
#include <memory>
#include <optional>
#include <string_view>

#include <fmt/format.h>
#include <fmt/chrono.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "common/bounded_threadsafe_queue.h"
#include "common/config.h"
#include "common/debug.h"
#include "common/io_file.h"
#include "common/logging/backend.h"
#include "common/logging/log.h"
#include "common/logging/log_entry.h"
#include "common/path_util.h"
#include "common/string_util.h"
#include "common/thread.h"

namespace Common::Log {
using namespace Common::FS;

namespace {

std::atomic_bool g_suppress_logging{true};

/* =========================
   Log Entry – agora apenas carrega a mensagem já formatada
   ========================= */
struct LogEntry {
    bool valid = false;
    std::chrono::microseconds timestamp;
    Class log_class{};
    Level log_level{};
    std::string_view filename{};
    unsigned int line = 0;
    std::string_view function{};
    std::string message;           // mensagem completa já formatada
    std::thread::id thread_id{};
};

/* =========================
   Backend Interface
   ========================= */
struct ILogBackend {
    virtual ~ILogBackend() = default;
    virtual void Write(const LogEntry&) = 0;
    virtual void Flush() = 0;
};

/* =========================
   Color Console Backend
   ========================= */
class ColorConsoleBackend final : public ILogBackend {
public:
    void Write(const LogEntry& entry) override {
        if (!enabled.load(std::memory_order_relaxed)) return;
        std::lock_guard lock(mutex);
        PrintColoredMessage(entry.log_level, entry.message);
    }

    void Flush() override {}

    void SetEnabled(bool value) {
        enabled.store(value, std::memory_order_relaxed);
    }

private:
    std::atomic_bool enabled{true};
    std::mutex mutex;
};

/* =========================
   File Backend – com rotação e limite de arquivos mantidos
   ========================= */
class FileBackend final : public ILogBackend {
public:
    explicit FileBackend(std::filesystem::path base_path, bool append)
        : base_path(std::move(base_path)), append_mode(append) {
        OpenNewFile();
    }

    void Write(const LogEntry& entry) override {
        std::lock_guard lock(mutex);

        if (!enabled) return;

        if (ShouldRotate()) {
            Rotate();
        }

        bytes_written += file.WriteString(entry.message + "\n");

        if (bytes_written > flush_threshold || entry.log_level >= Level::Error) {
            file.Flush();
        }
    }

    void Flush() override {
        std::lock_guard lock(mutex);
        file.Flush();
    }

private:
    void OpenNewFile() {
        file.Open(base_path, append_mode ? FileAccessMode::Append : FileAccessMode::Create,
                  FileType::TextFile);
        bytes_written = file.Tell();
        enabled = true;
    }

    bool ShouldRotate() const {
        return bytes_written >= max_file_size;
    }

    void Rotate() {
        file.Flush();
        file.Close();

        // Renomeia arquivos antigos (mantém até max_backups)
        for (int i = max_backups - 1; i >= 1; --i) {
            auto old_name = base_path.string() + "." + std::to_string(i);
            auto new_name = base_path.string() + "." + std::to_string(i + 1);
            std::filesystem::rename(old_name, new_name);  // ignora se não existir
        }

        std::filesystem::rename(base_path, base_path.string() + ".1");
        OpenNewFile();
        bytes_written = 0;
    }

private:
    IOFile file;
    std::filesystem::path base_path;
    bool append_mode = false;
    bool enabled = true;
    std::size_t bytes_written = 0;
    std::mutex mutex;

    // Configuráveis (podem vir de Config:: no futuro)
    static constexpr std::size_t max_file_size   = 128 * 1024 * 1024;  // 128 MB
    static constexpr std::size_t flush_threshold = 4 * 1024 * 1024;    // 4 MB
    static constexpr int max_backups = 5;
};

#ifdef _WIN32
class DebuggerBackend final : public ILogBackend {
public:
    void Write(const LogEntry& entry) override {
        std::string line = entry.message + "\n";
        ::OutputDebugStringW(UTF8ToUTF16W(line).c_str());
    }
    void Flush() override {}
};
#endif

/* =========================
   Logger Implementation
   ========================= */
class Impl {
public:
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    static Impl* Instance() {
        return instance.load(std::memory_order_acquire);
    }

    static void Initialize(std::string_view log_file_name, bool append = false) {
        std::call_once(init_flag, [&] {
            const auto log_dir = GetUserPath(PathType::LogDir);
            std::filesystem::create_directories(log_dir);

            Filter filter;
            filter.ParseFilterString(Config::getLogFilter());

            auto path = log_dir / (log_file_name.empty() ? LOG_FILE : log_file_name);
            auto* new_instance = new Impl(std::move(path), filter, append);
            instance.store(new_instance, std::memory_order_release);

            g_suppress_logging.store(false, std::memory_order_release);
        });
    }

    static void Shutdown() {
        g_suppress_logging.store(true, std::memory_order_release);

        Impl* old = instance.exchange(nullptr, std::memory_order_acq_rel);
        if (old) {
            old->Stop();
            delete old;
        }
    }

    static bool IsActive() {
        return instance.load(std::memory_order_acquire) != nullptr;
    }

    void Push(Class log_class, Level level,
              const char* filename, unsigned int line,
              const char* function,
              std::string_view format,
              const fmt::format_args& args) {

        if (g_suppress_logging.load(std::memory_order_relaxed) ||
            !filter.CheckMessage(log_class, level) ||
            !logging_enabled.load(std::memory_order_relaxed)) {
            return;
        }

        // Rate limiting simples (por thread)
        if (level >= Level::Warning) {
            auto now = std::chrono::steady_clock::now();
            if (now - last_high_level_msg < rate_limit_high) {
                return;  // drop
            }
            last_high_level_msg = now;
        }

        std::string full_message;
        try {
            full_message = fmt::format(
                "[{:>8}][{:>7}][{}:{} {}] {}",
                GetLogClassName(log_class),
                GetLevelName(level),
                filename ? filename : "?",
                line,
                function ? function : "?",
                fmt::vformat(fmt::runtime(format), args)
            );
        } catch (const fmt::format_error& e) {
            full_message = fmt::format(
                "[{:>8}][{:>7}][{}:{} {}] [FORMAT ERROR: {}]",
                GetLogClassName(log_class), GetLevelName(level),
                filename ? filename : "?", line,
                function ? function : "?", e.what()
            );
        }

        LogEntry entry{
            .valid = true,
            .timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - time_origin),
            .log_class = log_class,
            .log_level = level,
            .filename = filename ? std::string_view{filename} : std::string_view{},
            .line = line,
            .function = function ? std::string_view{function} : std::string_view{},
            .message = std::move(full_message),
            .thread_id = std::this_thread::get_id()
        };

        if (is_async.load(std::memory_order_relaxed)) {
            if (!queue.TryEmplace(std::move(entry))) {
                messages_dropped.fetch_add(1, std::memory_order_relaxed);
            }
        } else {
            WriteToBackends(entry);
        }

        messages_logged.fetch_add(1, std::memory_order_relaxed);
    }

    void SetColorConsoleEnabled(bool enabled) {
        if (color_console) color_console->SetEnabled(enabled);
    }

    void UpdateConfig() {
        logging_enabled.store(Config::getLoggingEnabled(), std::memory_order_relaxed);
        is_async.store(Config::getLogType() == "async", std::memory_order_relaxed);
    }

    std::size_t GetMessagesLogged() const { return messages_logged.load(std::memory_order_relaxed); }
    std::size_t GetMessagesDropped() const { return messages_dropped.load(std::memory_order_relaxed); }

private:
    explicit Impl(std::filesystem::path log_path, Filter filter, bool append)
        : filter(std::move(filter)), log_path(std::move(log_path)) {

        logging_enabled.store(Config::getLoggingEnabled(), std::memory_order_relaxed);
        is_async.store(Config::getLogType() == "async", std::memory_order_relaxed);

#ifdef _WIN32
        backends.emplace_back(std::make_unique<DebuggerBackend>());
#endif
        color_console = new ColorConsoleBackend();
        backends.emplace_back(std::unique_ptr<ILogBackend>(color_console));
        backends.emplace_back(std::make_unique<FileBackend>(this->log_path, append));

        if (is_async.load()) Start();
    }

    ~Impl() { Stop(); }

    void Start() {
        backend_thread = std::jthread([this](std::stop_token stop) {
            Common::SetCurrentThreadName("shadPS4:Log");

            LogEntry entry;
            while (!stop.stop_requested()) {
                if (queue.PopWait(entry, stop)) {
                    if (entry.valid) WriteToBackends(entry);
                }
            }

            // Drena fila no shutdown (máx 5 segundos)
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            while (std::chrono::steady_clock::now() < deadline && queue.TryPop(entry)) {
                if (entry.valid) WriteToBackends(entry);
            }
        });
    }

    void Stop() {
        if (backend_thread.joinable()) {
            backend_thread.request_stop();
            backend_thread.join();
        }
        FlushBackends();
    }

    void WriteToBackends(const LogEntry& entry) {
        for (auto& backend : backends) {
            try { backend->Write(entry); }
            catch (const std::exception& e) {
                fmt::print(stderr, "Log backend error: {}\n", e.what());
            }
        }
    }

    void FlushBackends() {
        for (auto& backend : backends) {
            try { backend->Flush(); }
            catch (...) {}
        }
    }

private:
    static inline std::atomic<Impl*> instance{nullptr};
    static inline std::once_flag init_flag;

    Filter filter;
    std::filesystem::path log_path;
    std::vector<std::unique_ptr<ILogBackend>> backends;
    ColorConsoleBackend* color_console = nullptr;

    MPSCQueue<LogEntry> queue;
    std::chrono::steady_clock::time_point time_origin = std::chrono::steady_clock::now();
    std::jthread backend_thread;

    std::atomic_bool logging_enabled{true};
    std::atomic_bool is_async{false};

    std::atomic<std::size_t> messages_logged{0};
    std::atomic<std::size_t> messages_dropped{0};

    // Rate limiting (por thread)
    thread_local inline static std::chrono::steady_clock::time_point last_high_level_msg{};
    static constexpr auto rate_limit_high = std::chrono::milliseconds(400);  // ~2.5 por segundo
};

} // namespace

// API pública (mantida compatível)
void Initialize(std::string_view log_file) {
    Impl::Initialize(log_file, false);
}

void InitializeAppend(std::string_view log_file) {
    Impl::Initialize(log_file, true);
}

void Deinitialize() {
    Impl::Shutdown();
}

bool IsActive() {
    return Impl::IsActive();
}

void SetColorConsoleBackendEnabled(bool enabled) {
    if (auto* impl = Impl::Instance()) impl->SetColorConsoleEnabled(enabled);
}

void UpdateConfiguration() {
    if (auto* impl = Impl::Instance()) impl->UpdateConfig();
}

std::size_t GetMessagesLogged() {
    return Impl::Instance() ? Impl::Instance()->GetMessagesLogged() : 0;
}

std::size_t GetMessagesDropped() {
    return Impl::Instance() ? Impl::Instance()->GetMessagesDropped() : 0;
}

void FmtLogMessageImpl(Class log_class, Level level,
                       const char* filename, unsigned int line,
                       const char* function,
                       const char* format,
                       const fmt::format_args& args) {
    if (!g_suppress_logging.load(std::memory_order_acquire)) {
        if (auto* impl = Impl::Instance()) {
            impl->Push(log_class, level, filename, line, function,
                       std::string_view{format}, args);
        }
    }
}

} // namespace Common::Log
