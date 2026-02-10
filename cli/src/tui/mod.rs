// Copyright 2024 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! TUI 模块
//!
//! 提供终端用户界面功能

mod app;
mod layout;
mod theme;
mod llm;
mod keys;
mod syntax;
mod audit;

pub mod panels;
pub mod widgets;

pub use app::*;
pub use layout::*;
pub use theme::*;
pub use keys::*;
pub use syntax::*;
pub use audit::*;

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
            }

            // Windows 控制台模式标志
            const ENABLE_ECHO_INPUT: u32 = 0x0004;
            const ENABLE_LINE_INPUT: u32 = 0x0002;
            const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
            const ENABLE_WINDOW_INPUT: u32 = 0x0008;
            const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x0200;
            const ENABLE_EXTENDED_FLAGS: u32 = 0x0080;
            const ENABLE_MOUSE_INPUT: u32 = 0x0010;
            const ENABLE_QUICK_EDIT_MODE: u32 = 0x0040;

            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                self.original_mode = Some(mode);
                debug!("Saved original console mode: 0x{:08X}", mode);

                // 设置 raw mode - 禁用所有可能导致回显的标志
                let raw_mode = (mode
                    & !ENABLE_ECHO_INPUT           // 禁用回显
                    & !ENABLE_LINE_INPUT           // 禁用行输入
                    & !ENABLE_PROCESSED_INPUT      // 禁用处理过的输入
                    & !ENABLE_QUICK_EDIT_MODE      // 禁用快速编辑模式
                    ) | ENABLE_WINDOW_INPUT        // 启用窗口输入
                    | ENABLE_VIRTUAL_TERMINAL_INPUT // 启用虚拟终端
                    | ENABLE_EXTENDED_FLAGS        // 启用扩展标志
                    | ENABLE_MOUSE_INPUT;          // 启用鼠标输入

                debug!("Setting raw console mode: 0x{:08X}", raw_mode);

                if SetConsoleMode(handle, raw_mode) == 0 {
                    debug!("Warning: SetConsoleMode failed");
                }

                // 验证模式是否正确设置
                let mut verify_mode: u32 = 0;
                if GetConsoleMode(handle, &mut verify_mode) != 0 {
                    debug!("Verified console mode: 0x{:08X}", verify_mode);
                    if verify_mode & ENABLE_ECHO_INPUT != 0 {
                        debug!("ERROR: ECHO is still enabled!");
                    }
                }
            } else {
                debug!("ERROR: GetConsoleMode failed");
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
    fn new() -> Self { Self }
    fn set_raw_mode(&mut self) -> Result<()> { Ok(()) }
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

        // 短暂延迟让模式生效
        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    // 然后启用 crossterm 的 raw mode
    enable_raw_mode()?;

    // Windows: 最终验证并确保模式正确
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawHandle;

        let stdin = io::stdin();
        let handle = stdin.as_raw_handle() as isize;

        unsafe {
            extern "system" {
                fn GetConsoleMode(handle: isize, mode: *mut u32) -> i32;
                fn SetConsoleMode(handle: isize, mode: u32) -> i32;
            }

            const ENABLE_ECHO_INPUT: u32 = 0x0004;
            const ENABLE_QUICK_EDIT_MODE: u32 = 0x0040;

            let mut mode: u32 = 0;
            if GetConsoleMode(handle, &mut mode) != 0 {
                // 如果回显或快速编辑模式仍然启用，强制禁用
                if mode & (ENABLE_ECHO_INPUT | ENABLE_QUICK_EDIT_MODE) != 0 {
                    debug!("Echo or QuickEdit still enabled, forcing disable");
                    let corrected = mode & !ENABLE_ECHO_INPUT & !ENABLE_QUICK_EDIT_MODE;
                    SetConsoleMode(handle, corrected);

                    // 最终验证
                    let mut final_mode: u32 = 0;
                    if GetConsoleMode(handle, &mut final_mode) != 0 {
                        debug!("Final console mode: 0x{:08X}", final_mode);
                    }
                }
            }
        }
    }

    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture
    )?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

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
