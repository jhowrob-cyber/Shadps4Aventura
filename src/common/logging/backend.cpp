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
#include <string_view>

#include <fmt/format.h>

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
   Lazy Log Entry
   ========================= */
struct LogEntry {
    bool valid = false;
    std::chrono::microseconds timestamp;
    Class log_class{};
    Level log_level{};
    const char* filename = nullptr;
    unsigned int line = 0;
    const char* function = nullptr;

    fmt::string_view format;
    fmt::format_args args;

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
   Shared formatter
   ========================= */
static void FormatLogLine(fmt::memory_buffer& buf, const LogEntry& e) {
    fmt::format_to(
        buf,
        "[{:>8}][{:>7}][{}:{} {}] ",
        GetLogClassName(e.log_class),
        GetLevelName(e.log_level),
        e.filename ? e.filename : "?",
        e.line,
        e.function ? e.function : "?"
    );

    try {
        fmt::vformat_to(buf, e.format, e.args);
    } catch (const fmt::format_error& err) {
        fmt::format_to(buf, "[FORMAT ERROR: {}]", err.what());
    }
}

/* =========================
   Color Console Backend
   ========================= */
class ColorConsoleBackend final : public ILogBackend {
public:
    void Write(const LogEntry& entry) override {
        if (!enabled.load(std::memory_order_relaxed))
            return;

        std::lock_guard lock(mutex);

        fmt::memory_buffer buf;
        FormatLogLine(buf, entry);

        PrintColoredMessage(
            entry.log_level,
            std::string_view(buf.data(), buf.size()));
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
   File Backend
   ========================= */
class FileBackend final : public ILogBackend {
public:
    explicit FileBackend(std::filesystem::path path, bool append)
        : log_path(std::move(path)) {
        file.Open(log_path,
                  append ? FileAccessMode::Append : FileAccessMode::Create,
                  FileType::TextFile);
    }

    void Write(const LogEntry& entry) override {
        std::lock_guard lock(mutex);

        fmt::memory_buffer buf;
        FormatLogLine(buf, entry);
        buf.push_back('\n');

        file.Write(buf.data(), buf.size());

        if (entry.log_level >= Level::Error)
            file.Flush();
    }

    void Flush() override {
        std::lock_guard lock(mutex);
        file.Flush();
    }

private:
    IOFile file;
    std::filesystem::path log_path;
    std::mutex mutex;
};

#ifdef _WIN32
/* =========================
   Debugger Backend (VS)
   ========================= */
class DebuggerBackend final : public ILogBackend {
public:
    void Write(const LogEntry& entry) override {
        fmt::memory_buffer buf;
        FormatLogLine(buf, entry);
        buf.push_back('\n');

        ::OutputDebugStringW(
            UTF8ToUTF16W(
                std::string_view(buf.data(), buf.size())).c_str());
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

    static void Initialize(std::string_view log_file, bool append) {
        std::call_once(init_flag, [&] {
            const auto log_dir = GetUserPath(PathType::LogDir);
            std::filesystem::create_directories(log_dir);

            Filter filter;
            filter.ParseFilterString(Config::getLogFilter());

            auto* impl = new Impl(log_dir / log_file, filter, append);
            instance.store(impl, std::memory_order_release);

            g_suppress_logging.store(false, std::memory_order_release);
        });
    }

    static void Shutdown() {
        g_suppress_logging.store(true, std::memory_order_release);

        if (auto* impl = instance.exchange(nullptr)) {
            impl->Stop();
            delete impl;
        }
    }

    void Push(Class log_class, Level level,
              const char* filename, unsigned int line,
              const char* function,
              std::string_view format,
              const fmt::format_args& args) {

        if (g_suppress_logging.load(std::memory_order_relaxed) ||
            !filter.CheckMessage(log_class, level) ||
            !logging_enabled.load(std::memory_order_relaxed))
            return;

        LogEntry entry{
            .valid = true,
            .timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - time_origin),
            .log_class = log_class,
            .log_level = level,
            .filename = filename,
            .line = line,
            .function = function,
            .format = fmt::string_view{format},
            .args = args,
            .thread_id = std::this_thread::get_id()
        };

        if (async.load(std::memory_order_relaxed)) {
            queue.TryEmplace(entry);
        } else {
            WriteToBackends(entry);
        }
    }

    void SetColorConsoleEnabled(bool enabled) {
        if (color_console)
            color_console->SetEnabled(enabled);
    }

private:
    Impl(std::filesystem::path path, Filter f, bool append)
        : filter(std::move(f)) {

#ifdef _WIN32
        backends.emplace_back(std::make_unique<DebuggerBackend>());
#endif
        color_console = new ColorConsoleBackend();
        backends.emplace_back(std::unique_ptr<ILogBackend>(color_console));
        backends.emplace_back(std::make_unique<FileBackend>(path, append));

        logging_enabled.store(Config::getLoggingEnabled());
        async.store(Config::getLogType() == "async");

        if (async.load())
            Start();
    }

    ~Impl() {
        Stop();
    }

    void Start() {
        backend_thread = std::jthread([this](std::stop_token stop) {
            Common::SetCurrentThreadName("shadPS4:Log");

            LogEntry entry;
            while (!stop.stop_requested()) {
                if (queue.PopWait(entry, stop) && entry.valid) {
                    WriteToBackends(entry);
                }
            }

            while (queue.TryPop(entry)) {
                if (entry.valid)
                    WriteToBackends(entry);
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
            backend->Write(entry);
        }
    }

    void FlushBackends() {
        for (auto& backend : backends) {
            backend->Flush();
        }
    }

private:
    static inline std::atomic<Impl*> instance{nullptr};
    static inline std::once_flag init_flag;

    Filter filter;
    std::vector<std::unique_ptr<ILogBackend>> backends;
    ColorConsoleBackend* color_console = nullptr;

    MPSCQueue<LogEntry> queue;
    std::chrono::steady_clock::time_point time_origin =
        std::chrono::steady_clock::now();

    std::jthread backend_thread;

    std::atomic_bool logging_enabled{true};
    std::atomic_bool async{false};
};

} // namespace

/* =========================
   Public API
   ========================= */
void Initialize(std::string_view log_file) {
    Impl::Initialize(log_file.empty() ? LOG_FILE : log_file, false);
}

void InitializeAppend(std::string_view log_file) {
    Impl::Initialize(log_file.empty() ? LOG_FILE : log_file, true);
}

void Deinitialize() {
    Impl::Shutdown();
}

bool IsActive() {
    return Impl::Instance() != nullptr;
}

void SetColorConsoleBackendEnabled(bool enabled) {
    if (auto* impl = Impl::Instance())
        impl->SetColorConsoleEnabled(enabled);
}

void FmtLogMessageImpl(Class log_class, Level level,
                       const char* filename, unsigned int line,
                       const char* function,
                       const char* format,
                       const fmt::format_args& args) {
    if (!g_suppress_logging.load(std::memory_order_relaxed)) {
        if (auto* impl = Impl::Instance()) {
            impl->Push(log_class, level,
                       filename, line, function,
                       std::string_view{format}, args);
        }
    }
}

} // namespace Common::Log
