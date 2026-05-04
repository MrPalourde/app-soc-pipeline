use serde_json::Value;

#[derive(Default, PartialEq)]
pub struct AuditdExecutionLog {
    pub cwd: String,
    pub exe: String,
    pub binary: String,
    pub loader: String,
    pub owner: String,
    pub permissions: String,
    pub command: String,
    pub args: Value,
    pub success: bool,
    pub proctitle: String,
    pub uid: String,
}

#[derive(PartialEq)]
pub enum AuditdLogType {
    Execution(AuditdExecutionLog),
}

#[derive(PartialEq)]
pub enum ServiceLogType {
    Auditd(AuditdLogType),
    NotSupported(()),
}

pub struct Log {
    pub ip: String,
    pub timestamp: i32,
    pub hostname: String,
    pub service: String,
    pub content: ServiceLogType,
}

impl From<AuditdExecutionLog> for AuditdLogType {
    fn from(log: AuditdExecutionLog) -> Self {
        AuditdLogType::Execution(log)
    }
}

impl From<AuditdLogType> for ServiceLogType {
    fn from(log: AuditdLogType) -> Self {
        ServiceLogType::Auditd(log)
    }
}
