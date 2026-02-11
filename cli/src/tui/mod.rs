// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! TUI 模块
//!
//! 提供终端用户界面功能

mod app;
mod audit;
mod keys;
mod layout;
mod llm;
mod syntax;
mod theme;

pub mod panels;
pub mod widgets;

pub use app::*;
pub use audit::*;
pub use keys::*;
pub use layout::*;
pub use syntax::*;
pub use theme::*;

use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use tracing::{debug, info};

/// Windows 控制台模式管理器
#[cfg(target_os = "windows")]
struct WindowsConsoleMode {
    original_mode: Option<u32>,
    stdin_handle: isize,
}

#[cfg(target_os = "windows")]
impl WindowsConsoleMode {
    fn new() -> Self {
        use std::os::windows::io::AsRawHandle;

        let stdin = io::stdin();

        Self {
            original_mode: None,
            stdin_handle: stdin.as_raw_handle() as isize,
        }
    }

    /// 设置 raw mode 并保存原始模式
    fn set_raw_mode(&mut self) -> Result<()> {
        use std::os::windows::io::AsRawHandle;

        let stdin = io::stdin();
        let handle = stdin.as_raw_handle() as isize;

        unsafe {
            extern "system" {
                fn GetConsoleMode(handle: isize, mode: *mut u32) -> i32;
                fn SetConsoleMode(handle: isize, mode: u32) -> i32;
                fn FlushConsoleInputBuffer(handle: isize) -> i32;
            }

            // Windows 控制台模式标志
            const ENABLE_ECHO_INPUT: u32 = 0x0004;
            const ENABLE_LINE_INPUT: u32 = 0x0002;
            const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
            const ENABLE_WINDOW_INPUT: u32 = 0x0008;
            const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
            const ENABLE_EXTENDED_FLAGS: u32 = 0x0080;
            const ENABLE_MOUSE_INPUT: u32 = 0x0010;

            // 首先清空输入缓冲区，防止残留事件
            FlushConsoleInputBuffer(handle);

            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                self.original_mode = Some(mode);
                debug!("Original console mode: 0x{:08X}", mode);

                // Raw mode: 完全禁用回显和行输入
                let raw_mode = ENABLE_WINDOW_INPUT
                    | ENABLE_VIRTUAL_TERMINAL_INPUT
                    | ENABLE_EXTENDED_FLAGS
                    | ENABLE_MOUSE_INPUT;

                debug!("Setting console mode: 0x{:08X} (ECHO={}, LINE={})",
                    raw_mode,
                    raw_mode & ENABLE_ECHO_INPUT != 0,
                    raw_mode & ENABLE_LINE_INPUT != 0);

                if SetConsoleMode(handle, raw_mode) == 0 {
                    debug!("SetConsoleMode failed");
                    return Err(anyhow::anyhow!("Failed to set console mode"));
                }

                // 再次清空输入缓冲区
                FlushConsoleInputBuffer(handle);

                // 验证
                let mut verify_mode: u32 = 0;
                if GetConsoleMode(handle, &mut verify_mode) != 0 {
                    debug!("Verified console mode: 0x{:08X}", verify_mode);
                    let echo_enabled = verify_mode & ENABLE_ECHO_INPUT != 0;
                    let line_enabled = verify_mode & ENABLE_LINE_INPUT != 0;
                    debug!("ECHO_INPUT: {}, LINE_INPUT: {}", echo_enabled, line_enabled);
                }
            } else {
                debug!("GetConsoleMode failed");
            }
        }
        Ok(())
    }

    /// 恢复原始控制台模式
    fn restore(&self) {
        if let Some(original) = self.original_mode {
            debug!("Restoring console mode: 0x{:08X}", original);
            unsafe {
                extern "system" {
                    fn SetConsoleMode(handle: isize, mode: u32) -> i32;
                }
                SetConsoleMode(self.stdin_handle, original);
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
struct WindowsConsoleMode;

#[cfg(not(target_os = "windows"))]
impl WindowsConsoleMode {
    fn new() -> Self {
        Self
    }
    fn set_raw_mode(&mut self) -> Result<()> {
        Ok(())
    }
    fn restore(&self) {}
}

/// TUI 入口点
pub async fn run_tui() -> Result<()> {
    info!("Starting TUI");

    // 创建应用并初始化
    let mut app = App::new()?;
    app.initialize().await?;

    // Windows: 设置控制台模式（必须在 crossterm 之前）
    let mut windows_console = WindowsConsoleMode::new();

    #[cfg(target_os = "windows")]
    {
        // 先设置 Windows 控制台模式
        windows_console.set_raw_mode()?;
        // 延迟让模式生效
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    // 然后启用 crossterm 的 raw mode
    enable_raw_mode()?;

    // Windows: 确保模式正确 - crossterm 的 enable_raw_mode 可能会覆盖我们的设置
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawHandle;

        let stdin = io::stdin();
        let handle = stdin.as_raw_handle() as isize;

        unsafe {
            extern "system" {
                fn GetConsoleMode(handle: isize, mode: *mut u32) -> i32;
                fn SetConsoleMode(handle: isize, mode: u32) -> i32;
                fn FlushConsoleInputBuffer(handle: isize) -> i32;
            }

            const ENABLE_ECHO_INPUT: u32 = 0x0004;
            const ENABLE_LINE_INPUT: u32 = 0x0002;
            const ENABLE_WINDOW_INPUT: u32 = 0x0008;
            const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
            const ENABLE_EXTENDED_FLAGS: u32 = 0x0080;
            const ENABLE_MOUSE_INPUT: u32 = 0x0010;

            // 清空输入缓冲区，防止残留事件
            FlushConsoleInputBuffer(handle);

            // 确保回显和行输入被禁用
            let desired_mode = ENABLE_WINDOW_INPUT
                | ENABLE_VIRTUAL_TERMINAL_INPUT
                | ENABLE_EXTENDED_FLAGS
                | ENABLE_MOUSE_INPUT;

            SetConsoleMode(handle, desired_mode);

            // 再次清空输入缓冲区
            FlushConsoleInputBuffer(handle);

            debug!("Console mode set to: 0x{:08X}", desired_mode);

            // 验证模式
            let mut final_mode: u32 = 0;
            if GetConsoleMode(handle, &mut final_mode) != 0 {
                debug!("Verified console mode: 0x{:08X}", final_mode);
                if final_mode & ENABLE_ECHO_INPUT != 0 {
                    debug!("WARNING: ECHO_INPUT is still enabled!");
                } else {
                    debug!("ECHO_INPUT is disabled.");
                }
                if final_mode & ENABLE_LINE_INPUT != 0 {
                    debug!("WARNING: LINE_INPUT is still enabled!");
                } else {
                    debug!("LINE_INPUT is disabled.");
                }
            }
        }

        // 额外延迟确保所有设置生效
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // 清空屏幕确保没有残留
    terminal.clear()?;

    // 运行应用主循环
    let res = app.run(&mut terminal);

    // 恢复终端
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    // 恢复 Windows 控制台模式
    windows_console.restore();

    // 处理结果
    if let Err(err) = res {
        eprintln!("TUI error: {:?}", err);
    }

    Ok(())
}

/// 运行 TUI 并执行审计
pub async fn run_tui_audit(project_path: String) -> Result<()> {
    debug!("Starting TUI audit for: {}", project_path);
    run_tui().await
}
