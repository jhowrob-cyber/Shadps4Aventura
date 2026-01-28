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
   Log Entry (IMPROVED)
   ========================= */
struct LogEntry {
    bool valid{false};

    std::chrono::microseconds timestamp;
    Class log_class;
    Level log_level;

    const char* filename{};
    unsigned int line{};
    const char* function{};

    const char* format{};
    // Store arguments safely for async logging
    fmt::dynamic_format_arg_store<fmt::format_context> args_store;

    std::string thread;
    
    // Pre-formatted message for sync mode
    std::optional<std::string> formatted_message;
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
   Lazy Formatter (with exception handling)
   ========================= */
inline std::string FormatLazy(const LogEntry& entry) {
    // Use pre-formatted message if available (sync mode)
    if (entry.formatted_message.has_value()) {
        return *entry.formatted_message;
    }

    try {
        std::string message = fmt::vformat(entry.format, entry.args_store);
        return fmt::format(
            "[{:>8}][{:>7}][{}:{} {}] {}",
            GetLogClassName(entry.log_class),
            GetLevelName(entry.log_level),
            entry.filename ? entry.filename : "?",
            entry.line,
            entry.function ? entry.function : "?",
            message);
    } catch (const fmt::format_error& e) {
        return fmt::format(
            "[{:>8}][{:>7}][{}:{} {}] [FORMAT ERROR: {}]",
            GetLogClassName(entry.log_class),
            GetLevelName(entry.log_level),
            entry.filename ? entry.filename : "?",
            entry.line,
            entry.function ? entry.function : "?",
            e.what());
    }
}

/* =========================
   Color Console Backend
   ========================= */
class ColorConsoleBackend final : public ILogBackend {
public:
    void Write(const LogEntry& entry) override {
        if (!enabled.load(std::memory_order_relaxed)) {
            return;
        }

        PrintColoredMessage(entry.log_level, FormatLazy(entry));
    }

    void Flush() override {}

    void SetEnabled(bool value) {
        enabled.store(value, std::memory_order_relaxed);
    }

private:
    std::atomic_bool enabled{true};
};

/* =========================
   File Backend (IMPROVED)
   ========================= */
class FileBackend final : public ILogBackend {
public:
    FileBackend(const std::filesystem::path& filename, bool append)
        : file(filename,
               append ? FileAccessMode::Append : FileAccessMode::Create,
               FileType::TextFile),
          base_filename(filename) {}

    void Write(const LogEntry& entry) override {
        std::lock_guard lock(mutex);

        if (!enabled) {
            return;
        }

        std::string formatted = FormatLazy(entry);
        bytes_written += file.WriteString(formatted.append(1, '\n'));

        constexpr auto write_limit = 100_MB;
        const bool should_flush = bytes_written > write_limit || 
                                 entry.log_level >= Level::Error;

        if (should_flush) {
            if (bytes_written > write_limit) {
                RotateLogFile();
            }
            file.Flush();
        }
    }

    void Flush() override {
        std::lock_guard lock(mutex);
        file.Flush();
    }

private:
    void RotateLogFile() {
        if (!enabled) {
            return;
        }

        // Log warning before rotation
        try {
            file.WriteString("[WARNING] Log file size limit reached, rotating...\n");
            file.Flush();
            file.Close();

            // Rename old file with timestamp
            auto timestamp = std::chrono::system_clock::now();
            auto time_t = std::chrono::system_clock::to_time_t(timestamp);
            
            auto old_path = base_filename;
            auto new_path = base_filename;
            new_path.replace_filename(
                fmt::format("{}.{}.old", 
                           base_filename.filename().string(),
                           time_t));

            std::filesystem::rename(base_filename, new_path);

            // Create new file
            file.Open(base_filename, FileAccessMode::Create, FileType::TextFile);
            bytes_written = 0;
            
        } catch (const std::exception& e) {
            // If rotation fails, disable logging to prevent issues
            enabled = false;
            fmt::print(stderr, "Failed to rotate log file: {}\n", e.what());
        }
    }

private:
    IOFile file;
    std::filesystem::path base_filename;
    bool enabled{true};
    std::size_t bytes_written{0};
    std::mutex mutex;
};

#ifdef _WIN32
/* =========================
   Debugger Backend
   ========================= */
class DebuggerBackend final : public ILogBackend {
public:
    void Write(const LogEntry& entry) override {
        ::OutputDebugStringW(
            UTF8ToUTF16W(FormatLazy(entry).append(1, '\n')).c_str());
    }

    void Flush() override {}
};
#endif

/* =========================
   Logger Implementation (IMPROVED)
   ========================= */
class Impl {
public:
    // Non-copyable, non-movable
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;
    Impl(Impl&&) = delete;
    Impl& operator=(Impl&&) = delete;

    static Impl* Instance() {
        return instance.load(std::memory_order_acquire);
    }

    static void Initialize(std::string_view log_file, bool append) {
        std::call_once(init_flag, [&] {
            const auto& log_dir = GetUserPath(PathType::LogDir);
            std::filesystem::create_directories(log_dir);

            Filter filter;
            filter.ParseFilterString(Config::getLogFilter());

            auto new_instance = new Impl(log_dir / log_file, filter, append);
            instance.store(new_instance, std::memory_order_release);
            
            g_suppress_logging.store(false, std::memory_order_release);
        });
    }

    static void Shutdown() {
        g_suppress_logging.store(true, std::memory_order_release);
        
        // Ensure no new logs are accepted before destroying instance
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        
        Impl* inst = instance.exchange(nullptr, std::memory_order_acq_rel);
        if (inst) {
            inst->Stop();
            delete inst;
        }
        
        // Reset init flag for potential re-initialization
        init_flag.~once_flag();
        new (&init_flag) std::once_flag();
    }

    static bool IsActive() {
        return instance.load(std::memory_order_acquire) != nullptr;
    }

    void Push(Class log_class, Level level,
              const char* filename, unsigned int line,
              const char* function,
              const char* format,
              const fmt::format_args& args) {
        
        if (!filter.CheckMessage(log_class, level) ||
            !logging_enabled.load(std::memory_order_relaxed)) {
            return;
        }

        LogEntry entry{
            .valid = true,
            .timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - time_origin),
            .log_class = log_class,
            .log_level = level,
            .filename = filename,
            .line = line,
            .function = function,
            .format = format,
            .thread = GetThreadName(),
        };

        // Store arguments safely for async mode
        entry.args_store = fmt::dynamic_format_arg_store<fmt::format_context>();
        fmt::vformat_to(std::back_inserter(entry.args_store), format, args);

        if (is_async.load(std::memory_order_relaxed)) {
            queue.EmplaceWait(std::move(entry));
        } else {
            // Format once for all backends in sync mode
            try {
                std::string message = fmt::vformat(format, args);
                entry.formatted_message = fmt::format(
                    "[{:>8}][{:>7}][{}:{} {}] {}",
                    GetLogClassName(log_class),
                    GetLevelName(level),
                    filename ? filename : "?",
                    line,
                    function ? function : "?",
                    message);
            } catch (const fmt::format_error& e) {
                entry.formatted_message = fmt::format(
                    "[{:>8}][{:>7}][{}:{} {}] [FORMAT ERROR: {}]",
                    GetLogClassName(log_class),
                    GetLevelName(level),
                    filename ? filename : "?",
                    line,
                    function ? function : "?",
                    e.what());
            }
            
            WriteToBackends(entry);
        }

        // Update statistics
        messages_logged.fetch_add(1, std::memory_order_relaxed);
    }

    void SetColorConsoleEnabled(bool enabled) {
        if (color_console) {
            color_console->SetEnabled(enabled);
        }
    }

    void UpdateConfig() {
        logging_enabled.store(Config::getLoggingEnabled(), std::memory_order_relaxed);
        is_async.store(Config::getLogType() == "async", std::memory_order_relaxed);
    }

    // Statistics
    std::size_t GetMessagesLogged() const {
        return messages_logged.load(std::memory_order_relaxed);
    }

    std::size_t GetMessagesDropped() const {
        return messages_dropped.load(std::memory_order_relaxed);
    }

private:
    Impl(const std::filesystem::path& file,
         const Filter& filter_,
         bool append)
        : filter(filter_) {

        // Cache config values
        logging_enabled.store(Config::getLoggingEnabled(), std::memory_order_relaxed);
        is_async.store(Config::getLogType() == "async", std::memory_order_relaxed);

#ifdef _WIN32
        backends.emplace_back(std::make_unique<DebuggerBackend>());
#endif
        color_console = new ColorConsoleBackend();
        backends.emplace_back(std::unique_ptr<ILogBackend>(color_console));
        backends.emplace_back(std::make_unique<FileBackend>(file, append));

        // Start automatically
        Start();
    }

    ~Impl() {
        Stop();
    }

    void Start() {
        if (!is_async.load(std::memory_order_relaxed)) {
            return; // No thread needed for sync mode
        }

        backend_thread = std::jthread([this](std::stop_token stop) {
            Common::SetCurrentThreadName("shadPS4:Log");

            LogEntry entry{};
            while (!stop.stop_requested()) {
                if (!queue.PopWait(entry, stop)) {
                    continue;
                }
                if (entry.valid) {
                    WriteToBackends(entry);
                }
            }

            // Drain queue with timeout during shutdown
            auto deadline = std::chrono::steady_clock::now() + 
                           std::chrono::seconds(5);
            
            while (std::chrono::steady_clock::now() < deadline && 
                   queue.TryPop(entry)) {
                if (entry.valid) {
                    WriteToBackends(entry);
                } else {
                    messages_dropped.fetch_add(1, std::memory_order_relaxed);
                }
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
            try {
                backend->Write(entry);
            } catch (const std::exception& e) {
                // Prevent backend exceptions from crashing the logger
                fmt::print(stderr, "Backend write error: {}\n", e.what());
            }
        }
    }

    void FlushBackends() {
        for (auto& backend : backends) {
            try {
                backend->Flush();
            } catch (const std::exception& e) {
                fmt::print(stderr, "Backend flush error: {}\n", e.what());
            }
        }
    }

    std::string GetThreadName() {
        // Cache thread names to avoid repeated allocations
        thread_local std::string cached_name = Common::GetCurrentThreadName();
        return cached_name;
    }

private:
    static inline std::atomic<Impl*> instance{nullptr};
    static inline std::once_flag init_flag;

    Filter filter;
    std::vector<std::unique_ptr<ILogBackend>> backends;
    ColorConsoleBackend* color_console{nullptr};

    MPSCQueue<LogEntry> queue;
    std::chrono::steady_clock::time_point time_origin{
        std::chrono::steady_clock::now()};
    std::jthread backend_thread;

    // Cached config values
    std::atomic_bool logging_enabled{true};
    std::atomic_bool is_async{false};

    // Statistics
    std::atomic<std::size_t> messages_logged{0};
    std::atomic<std::size_t> messages_dropped{0};
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
    return Impl::IsActive();
}

void Start() {
    // Now handled automatically in constructor
    // Kept for API compatibility
}

void Stop() {
    // Now handled automatically in destructor
    // Kept for API compatibility
}

void SetColorConsoleBackendEnabled(bool enabled) {
    if (auto* impl = Impl::Instance()) {
        impl->SetColorConsoleEnabled(enabled);
    }
}

void UpdateConfiguration() {
    if (auto* impl = Impl::Instance()) {
        impl->UpdateConfig();
    }
}

std::size_t GetMessagesLogged() {
    if (auto* impl = Impl::Instance()) {
        return impl->GetMessagesLogged();
    }
    return 0;
}

std::size_t GetMessagesDropped() {
    if (auto* impl = Impl::Instance()) {
        return impl->GetMessagesDropped();
    }
    return 0;
}

void FmtLogMessageImpl(Class log_class, Level level,
                       const char* filename, unsigned int line,
                       const char* function,
                       const char* format,
                       const fmt::format_args& args) {
    if (!g_suppress_logging.load(std::memory_order_acquire)) {
        if (auto* impl = Impl::Instance()) {
            impl->Push(log_class, level, filename, line,
                       function, format, args);
        }
    }
}

} // namespace Common::Log
