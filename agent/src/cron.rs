// Copyright 2026 CTX-Audit
// SPDX-License-Identifier: Apache-2.0

//! cron：daemon 内轻量定时器（M3）
//!
//! - 5 字段 cron 最小解析器（分 时 日 月 周），支持 `*`、`*/n`、逗号、范围 `a-b`、`a-b/n`；
//!   workspace 锁内无 cron crate，故手写，不引新依赖。
//! - 任务持久化 `<daemon_state_dir>/cron.json`，增删即写盘；
//! - fire = 以任务 target 起跑一轮 runner（经 RoundLauncher 抽象，daemon 宿主实现）；
//! - 防重入：同一 job 上一轮未结束则跳过本次 fire 并记日志。
//!
//! 简化语义：day-of-month 与 day-of-week 同时限定时取 AND（标准 cron 为 OR），
//! M3 场景（每天/每 N 分钟一轮）不受影响，注释明示。

use async_trait::async_trait;
use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

// ── cron 表达式 ─────────────────────────────────────────

/// 字段位掩码（分/秒级字段最多 60 值，u64 足够）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FieldSet {
    /// `*`
    Any,
    /// 命中的值集合（位掩码）
    Values(u64),
}

impl FieldSet {
    fn matches(&self, value: u32) -> bool {
        match self {
            FieldSet::Any => true,
            FieldSet::Values(mask) => value < 64 && (mask & (1u64 << value)) != 0,
        }
    }
}

/// cron 表达式解析错误
#[derive(Debug, thiserror::Error)]
pub enum CronParseError {
    /// 字段数错误
    #[error("cron 表达式应为 5 个字段（分 时 日 月 周），实际 {0} 个")]
    FieldCount(usize),

    /// 字段非法
    #[error("字段 \"{0}\" 非法: {1}")]
    InvalidField(String, String),
}

/// 5 字段 cron 表达式
#[derive(Debug, Clone)]
pub struct CronSchedule {
    minutes: FieldSet,
    hours: FieldSet,
    days_of_month: FieldSet,
    months: FieldSet,
    days_of_week: FieldSet,
}

impl CronSchedule {
    /// 解析 5 字段 cron 表达式
    pub fn parse(expr: &str) -> Result<Self, CronParseError> {
        let fields: Vec<&str> = expr.split_whitespace().collect();
        if fields.len() != 5 {
            return Err(CronParseError::FieldCount(fields.len()));
        }
        Ok(Self {
            minutes: parse_field(fields[0], 0, 59)?,
            hours: parse_field(fields[1], 0, 23)?,
            days_of_month: parse_field(fields[2], 1, 31)?,
            months: parse_field(fields[3], 1, 12)?,
            days_of_week: parse_field(fields[4], 0, 6)?,
        })
    }

    /// 判断指定时刻是否命中（分钟精度）
    pub fn matches(&self, dt: &DateTime<Utc>) -> bool {
        self.minutes.matches(dt.minute())
            && self.hours.matches(dt.hour())
            && self.days_of_month.matches(dt.day())
            && self.months.matches(dt.month())
            // chrono: num_days_from_sunday 0=周日，与 cron dow 一致
            && self.days_of_week.matches(dt.weekday().num_days_from_sunday())
    }

    /// 计算 now 之后的下一次触发时间（逐分钟扫描，上限一年）
    pub fn next_after(&self, now: &DateTime<Utc>) -> Option<DateTime<Utc>> {
        // 对齐到下一分钟（秒清零）
        let mut candidate = *now + chrono::Duration::minutes(1);
        candidate = candidate
            .with_second(0)
            .and_then(|d| d.with_nanosecond(0))?;
        for _ in 0..366 * 24 * 60 {
            if self.matches(&candidate) {
                return Some(candidate);
            }
            candidate += chrono::Duration::minutes(1);
        }
        None
    }
}

/// 解析单个字段：`*`、`*/n`、`a`、`a,b,c`、`a-b`、`a-b/n`
fn parse_field(spec: &str, min: u32, max: u32) -> Result<FieldSet, CronParseError> {
    let invalid = |reason: &str| CronParseError::InvalidField(spec.to_string(), reason.to_string());

    if spec == "*" {
        return Ok(FieldSet::Any);
    }

    let mut mask: u64 = 0;
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(invalid("空段"));
        }

        // 拆 step：base/n
        let (base, step) = match part.split_once('/') {
            Some((b, s)) => {
                let step: u32 = s.parse().map_err(|_| invalid("步长非数字"))?;
                if step == 0 {
                    return Err(invalid("步长不能为 0"));
                }
                (b, step)
            }
            None => (part, 1),
        };

        // 拆范围：a-b 或单值或 *
        let (lo, hi) = if base == "*" {
            (min, max)
        } else if let Some((a, b)) = base.split_once('-') {
            let lo: u32 = a.parse().map_err(|_| invalid("范围下界非数字"))?;
            let hi: u32 = b.parse().map_err(|_| invalid("范围上界非数字"))?;
            if lo > hi {
                return Err(invalid("范围下界大于上界"));
            }
            (lo, hi)
        } else {
            let v: u32 = base.parse().map_err(|_| invalid("非数字"))?;
            // 单值带步长无意义但容忍：只取该值
            (v, v)
        };

        if lo < min || hi > max {
            return Err(invalid(&format!("超出取值范围 {}-{}", min, max)));
        }
        let mut v = lo;
        while v <= hi {
            mask |= 1u64 << v;
            v += step;
        }
    }

    Ok(FieldSet::Values(mask))
}

// ── 任务存储 ────────────────────────────────────────────

/// cron 任务
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJob {
    /// 任务 ID
    pub id: String,
    /// 5 字段 cron 表达式
    pub schedule: String,
    /// 审计目标（路径或 git URL）
    pub target: String,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 上次 fire 时间
    #[serde(default)]
    pub last_fired: Option<DateTime<Utc>>,
}

/// 任务存储（JSON 文件，增删即写盘）
pub struct CronStore {
    path: PathBuf,
    jobs: Vec<CronJob>,
}

impl CronStore {
    /// 打开（不存在则视为空）
    pub fn open(path: PathBuf) -> Self {
        let jobs = std::fs::read_to_string(&path)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default();
        Self { path, jobs }
    }

    /// 从磁盘重载（CLI 增删后调度器跟进）
    pub fn reload(&mut self) {
        if let Ok(content) = std::fs::read_to_string(&self.path) {
            if let Ok(jobs) = serde_json::from_str(&content) {
                self.jobs = jobs;
            }
        }
    }

    /// 任务列表
    pub fn list(&self) -> &[CronJob] {
        &self.jobs
    }

    /// 新增任务（schedule 先校验合法性），返回任务 ID
    pub fn add(&mut self, schedule: &str, target: &str) -> Result<CronJob, CronParseError> {
        CronSchedule::parse(schedule)?;
        let job = CronJob {
            id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            schedule: schedule.to_string(),
            target: target.to_string(),
            created_at: Utc::now(),
            last_fired: None,
        };
        self.jobs.push(job.clone());
        self.save();
        Ok(job)
    }

    /// 删除任务
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.jobs.len();
        self.jobs.retain(|j| j.id != id);
        let removed = self.jobs.len() != before;
        if removed {
            self.save();
        }
        removed
    }

    /// 记录 fire 时间
    pub fn mark_fired(&mut self, id: &str, when: DateTime<Utc>) {
        if let Some(job) = self.jobs.iter_mut().find(|j| j.id == id) {
            job.last_fired = Some(when);
            self.save();
        }
    }

    /// 写盘（失败只记日志，不中断调度）
    fn save(&self) {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string_pretty(&self.jobs) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.path, json) {
                    tracing::warn!("cron 任务写盘失败: {}", e);
                }
            }
            Err(e) => tracing::warn!("cron 任务序列化失败: {}", e),
        }
    }

    /// 存储文件路径
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ── 调度器 ──────────────────────────────────────────────

/// 轮次启动器抽象（daemon agent 宿主实现；测试用 mock）
#[async_trait]
pub trait RoundLauncher: Send + Sync {
    /// 起跑一轮并等待结束；返回 Err 表示轮次失败/中止
    async fn launch(&self, target: &str, round_id: &str) -> Result<(), String>;
}

/// cron 调度器（每分钟对齐 tick）
pub struct CronScheduler {
    store: CronStore,
    launcher: Arc<dyn RoundLauncher>,
    /// 正在执行的 job id（防重入）
    active: Arc<Mutex<HashSet<String>>>,
    /// 各 job 上次 fire 的分钟戳（防同一分钟内重复 fire）
    fired_minutes: HashMap<String, String>,
}

impl CronScheduler {
    /// 创建调度器
    pub fn new(store: CronStore, launcher: Arc<dyn RoundLauncher>) -> Self {
        Self {
            store,
            launcher,
            active: Arc::new(Mutex::new(HashSet::new())),
            fired_minutes: HashMap::new(),
        }
    }

    /// 检查指定时刻并 fire 到期任务（测试可直接注入时间）
    pub fn tick(&mut self, now: DateTime<Utc>) {
        let minute_key = now.format("%Y%m%d%H%M").to_string();

        // 收集到期任务（先计算，避免持有 store 借用跨 spawn）
        let due: Vec<CronJob> = self
            .store
            .list()
            .iter()
            .filter(|job| {
                let Ok(schedule) = CronSchedule::parse(&job.schedule) else {
                    tracing::warn!("cron 任务 {} 表达式非法，跳过: {}", job.id, job.schedule);
                    return false;
                };
                schedule.matches(&now)
            })
            .cloned()
            .collect();

        for job in due {
            // 防同一分钟重复 fire
            if self.fired_minutes.get(&job.id) == Some(&minute_key) {
                continue;
            }
            // 防重入：上一轮未结束跳过
            {
                let active = self.active.lock().unwrap();
                if active.contains(&job.id) {
                    tracing::warn!(
                        "cron 任务 {} 上一轮仍在执行，跳过本次 fire（目标 {}）",
                        job.id,
                        job.target
                    );
                    continue;
                }
            }

            let round_id = format!("cron-{}-{}", job.id, now.format("%Y%m%d-%H%M"));
            tracing::info!(
                "cron fire: 任务 {} → 轮次 {}（目标 {}）",
                job.id,
                round_id,
                job.target
            );

            self.active.lock().unwrap().insert(job.id.clone());
            self.fired_minutes.insert(job.id.clone(), minute_key.clone());
            self.store.mark_fired(&job.id, now);

            let launcher = self.launcher.clone();
            let active = self.active.clone();
            let job_id = job.id.clone();
            let target = job.target.clone();
            tokio::spawn(async move {
                let result = launcher.launch(&target, &round_id).await;
                match result {
                    Ok(()) => tracing::info!("cron 轮次 {} 完成", round_id),
                    Err(e) => tracing::warn!("cron 轮次 {} 失败: {}", round_id, e),
                }
                active.lock().unwrap().remove(&job_id);
            });
        }
    }

    /// 运行调度循环：每分钟边界 tick，收到 shutdown 退出
    pub async fn run(mut self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        loop {
            // 对齐下一分钟边界
            let now = Utc::now();
            let secs_to_next_minute = 60 - now.second() as u64;
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(secs_to_next_minute)) => {
                    // 从磁盘重载（CLI 增删即时生效）
                    self.store.reload();
                    self.tick(Utc::now());
                }
                _ = shutdown.changed() => {
                    tracing::info!("cron 调度器已停止");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> DateTime<Utc> {
        chrono::NaiveDate::from_ymd_opt(y, mo, d)
            .unwrap()
            .and_hms_opt(h, mi, 0)
            .unwrap()
            .and_utc()
    }

    // ── 表达式解析与匹配 ──

    #[test]
    fn test_parse_star() {
        let s = CronSchedule::parse("* * * * *").unwrap();
        assert!(s.matches(&at(2026, 8, 9, 0, 0)));
        assert!(s.matches(&at(2026, 8, 9, 13, 47)));
    }

    #[test]
    fn test_parse_step() {
        let s = CronSchedule::parse("*/15 * * * *").unwrap();
        assert!(s.matches(&at(2026, 8, 9, 10, 0)));
        assert!(s.matches(&at(2026, 8, 9, 10, 15)));
        assert!(s.matches(&at(2026, 8, 9, 10, 45)));
        assert!(!s.matches(&at(2026, 8, 9, 10, 7)));
    }

    #[test]
    fn test_parse_list_and_range() {
        let s = CronSchedule::parse("0,30 1-3 * * *").unwrap();
        assert!(s.matches(&at(2026, 8, 9, 1, 0)));
        assert!(s.matches(&at(2026, 8, 9, 2, 30)));
        assert!(s.matches(&at(2026, 8, 9, 3, 0)));
        assert!(!s.matches(&at(2026, 8, 9, 4, 0)));
        assert!(!s.matches(&at(2026, 8, 9, 1, 15)));

        // 范围带步长
        let s = CronSchedule::parse("0-10/5 * * * *").unwrap();
        assert!(s.matches(&at(2026, 8, 9, 0, 0)));
        assert!(s.matches(&at(2026, 8, 9, 0, 5)));
        assert!(s.matches(&at(2026, 8, 9, 0, 10)));
        assert!(!s.matches(&at(2026, 8, 9, 0, 3)));
    }

    #[test]
    fn test_parse_day_of_week() {
        // 2026-08-09 是周日（dow=0）
        let s = CronSchedule::parse("0 3 * * 0").unwrap();
        assert!(s.matches(&at(2026, 8, 9, 3, 0)));
        assert!(!s.matches(&at(2026, 8, 10, 3, 0))); // 周一不匹配
    }

    #[test]
    fn test_parse_invalid() {
        assert!(CronSchedule::parse("* * * *").is_err()); // 4 字段
        assert!(CronSchedule::parse("61 * * * *").is_err()); // 超范围
        assert!(CronSchedule::parse("*/0 * * * *").is_err()); // 步长 0
        assert!(CronSchedule::parse("abc * * * *").is_err());
        assert!(CronSchedule::parse("5-1 * * * *").is_err()); // 倒置范围
    }

    #[test]
    fn test_next_after() {
        let s = CronSchedule::parse("0 3 * * *").unwrap();
        let next = s.next_after(&at(2026, 8, 9, 3, 0)).unwrap();
        // 当天 03:00 已过（从下一分钟起算），应为次日 03:00
        assert_eq!(next, at(2026, 8, 10, 3, 0));

        let next = s.next_after(&at(2026, 8, 9, 2, 59)).unwrap();
        assert_eq!(next, at(2026, 8, 9, 3, 0));

        let s = CronSchedule::parse("*/20 * * * *").unwrap();
        let next = s.next_after(&at(2026, 8, 9, 10, 7)).unwrap();
        assert_eq!(next, at(2026, 8, 9, 10, 20));
    }

    // ── 任务存储 ──

    #[test]
    fn test_store_add_remove_persist() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-audit-cron-test-{}",
            uuid::Uuid::new_v4()
        ));
        let path = dir.join("cron.json");

        let mut store = CronStore::open(path.clone());
        assert!(store.list().is_empty());

        let job = store.add("*/5 * * * *", "/tmp/target").unwrap();
        assert!(path.exists(), "增即写盘");

        // 重新打开可见
        let store2 = CronStore::open(path.clone());
        assert_eq!(store2.list().len(), 1);
        assert_eq!(store2.list()[0].target, "/tmp/target");

        // 非法表达式不入库
        assert!(store.add("bad expr", "/tmp/x").is_err());
        assert_eq!(store.list().len(), 1);

        // 删除即写盘
        assert!(store.remove(&job.id));
        assert!(!store.remove(&job.id));
        let store3 = CronStore::open(path.clone());
        assert!(store3.list().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    // ── 调度器：fire 与防重入 ──

    struct MockLauncher {
        calls: Arc<Mutex<Vec<String>>>,
        /// 阻塞 launch 直到放行（模拟长轮次）
        release: Arc<tokio::sync::Notify>,
        block: bool,
    }

    #[async_trait]
    impl RoundLauncher for MockLauncher {
        async fn launch(&self, target: &str, round_id: &str) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("{}:{}", target, round_id));
            if self.block {
                self.release.notified().await;
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_scheduler_fire_and_reentry_guard() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-audit-cron-sched-{}",
            uuid::Uuid::new_v4()
        ));
        let mut store = CronStore::open(dir.join("cron.json"));
        store.add("* * * * *", "/tmp/target").unwrap();
        let job_id = store.list()[0].id.clone();

        let calls = Arc::new(Mutex::new(Vec::new()));
        let release = Arc::new(tokio::sync::Notify::new());
        let launcher = Arc::new(MockLauncher {
            calls: calls.clone(),
            release: release.clone(),
            block: true,
        });
        let mut scheduler = CronScheduler::new(store, launcher);

        // 第一次 tick：fire
        scheduler.tick(at(2026, 8, 9, 10, 0));
        tokio::task::yield_now().await;
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(calls.lock().unwrap()[0].contains(&format!("cron-{}-20260809-1000", job_id)));

        // 第二次 tick（下一分钟）：上一轮未结束 → 防重入跳过
        scheduler.tick(at(2026, 8, 9, 10, 1));
        tokio::task::yield_now().await;
        assert_eq!(calls.lock().unwrap().len(), 1, "重入应被跳过");

        // 放行上轮 → 再 tick 可再次 fire
        release.notify_waiters();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        scheduler.tick(at(2026, 8, 9, 10, 2));
        tokio::task::yield_now().await;
        assert_eq!(calls.lock().unwrap().len(), 2, "上轮结束后应恢复 fire");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn test_scheduler_same_minute_dedup() {
        let dir = std::env::temp_dir().join(format!(
            "ctx-audit-cron-dedup-{}",
            uuid::Uuid::new_v4()
        ));
        let mut store = CronStore::open(dir.join("cron.json"));
        store.add("* * * * *", "/tmp/t").unwrap();

        let calls = Arc::new(Mutex::new(Vec::new()));
        let launcher = Arc::new(MockLauncher {
            calls: calls.clone(),
            release: Arc::new(tokio::sync::Notify::new()),
            block: false,
        });
        let mut scheduler = CronScheduler::new(store, launcher);

        let t = at(2026, 8, 9, 10, 0);
        scheduler.tick(t);
        scheduler.tick(t); // 同一分钟重复 tick
        tokio::task::yield_now().await;
        assert_eq!(calls.lock().unwrap().len(), 1, "同一分钟只 fire 一次");

        std::fs::remove_dir_all(&dir).ok();
    }
}
