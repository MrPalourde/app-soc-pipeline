use serde_json::Value;

#[derive(Default, PartialEq, Debug)]
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

#[derive(Default, PartialEq, Debug)]
pub struct AuditdUserLoginLog {
    pub address: String,
    pub exe: String,
    pub result: String,
    pub user_id: String,
}

#[derive(PartialEq, Debug)]
pub enum AuditdLogType {
    Execution(AuditdExecutionLog),
    UserLogin(AuditdUserLoginLog),
}

#[derive(PartialEq, Debug)]
pub enum ServiceLogType {
    Auditd(AuditdLogType),
    NotSupported(()),
}

#[derive(Debug)]
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

impl From<AuditdUserLoginLog> for AuditdLogType {
    fn from(log: AuditdUserLoginLog) -> Self {
        AuditdLogType::UserLogin(log)
    }
}

impl From<AuditdLogType> for ServiceLogType {
    fn from(log: AuditdLogType) -> Self {
        ServiceLogType::Auditd(log)
    }
}
