//! 事件系统模块
//!
//! 提供事件总线、事件管理和持久化功能

pub mod bus;
pub mod emitter;
pub mod manager;
pub mod persistence;

// 重新导出常用类型
pub use bus::{EventBusV2, EventBusV2Config};
pub use emitter::TauriEventEmitter;
pub use manager::{EventEmitter, EventManager};
pub use persistence::EventPersistence;
