//! Fixed system endpoints for one live, block-only PF session.

use std::num::NonZeroU32;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};

use anyhow::{Context, anyhow};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tunlatch_ipc::privileged_endpoint::SystemListeners;
use tunlatch_ipc::protocol::{
    ErrorCode, PROTOCOL_VERSION, PfProtection, PfSessionPhase, PfSessionStatus, PfStopOutcome,
    Reply, Request, RequestEnvelope, ResponseEnvelope,
};
use tunlatch_ipc::{IpcError, REQUEST_TIMEOUT, frame};
use tunlatch_platform::pf::session::{
    BlockingSession, InterruptedSession, SessionStatus, StopOperation,
};

use tunlatchd::MAX_CLIENTS;

enum Command {
    Start,
    Stop,
    Exit,
}

struct SharedState {
    status: PfSessionStatus,
    closing: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InterruptOutcome {
    AwaitStartup,
    AwaitStop,
    Exit,
}

#[derive(Clone)]
struct Controller {
    shared: Arc<Mutex<SharedState>>,
    updates: watch::Sender<PfSessionStatus>,
    commands: SyncSender<Command>,
}

impl Controller {
    fn new() -> (
        Self,
        mpsc::Receiver<Command>,
        watch::Receiver<PfSessionStatus>,
    ) {
        let status = PfSessionStatus {
            actual_protection: PfProtection::Unknown,
            phase: PfSessionPhase::Starting,
            last_stop: None,
        };
        let (updates, receiver) = watch::channel(status);
        let (commands, queue) = mpsc::sync_channel(1);
        (
            Self {
                shared: Arc::new(Mutex::new(SharedState {
                    status,
                    closing: false,
                })),
                updates,
                commands,
            },
            queue,
            receiver,
        )
    }

    fn status(&self) -> PfSessionStatus {
        self.shared.lock().map_or(
            PfSessionStatus {
                actual_protection: PfProtection::Unknown,
                phase: PfSessionPhase::Unavailable,
                last_stop: None,
            },
            |shared| shared.status,
        )
    }

    fn publish(&self, status: PfSessionStatus) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.status = status;
            self.updates.send_replace(status);
        }
    }

    fn stop(&self) -> Result<Reply, ErrorCode> {
        let mut shared = self
            .shared
            .lock()
            .map_err(|_| ErrorCode::PfOperationUnavailable)?;
        if shared.closing {
            return Err(ErrorCode::ServiceShuttingDown);
        }
        match shared.status.phase {
            PfSessionPhase::Starting | PfSessionPhase::Stopping => {
                return Err(ErrorCode::PfOperationBusy);
            }
            PfSessionPhase::Stopped => return Ok(Reply::PfAlreadyStopped {}),
            PfSessionPhase::DetachUnconfirmed
            | PfSessionPhase::ClearUnconfirmed
            | PfSessionPhase::ReleaseUnconfirmed => {
                return Err(ErrorCode::PfOperationUnconfirmed);
            }
            PfSessionPhase::StartupInterrupted
            | PfSessionPhase::StartupFailed
            | PfSessionPhase::Unavailable => return Err(ErrorCode::PfOperationUnavailable),
            PfSessionPhase::Attached
            | PfSessionPhase::Detached
            | PfSessionPhase::Cleared
            | PfSessionPhase::Retiring => {}
        }
        self.enqueue_stop(&mut shared, false)?;
        Ok(Reply::PfStopAccepted {})
    }

    fn enqueue_stop(&self, shared: &mut SharedState, exit_after: bool) -> Result<(), ErrorCode> {
        // Hold the state lock across enqueue and publication: no concurrent request can
        // queue an implicit retry, and a fast worker cannot publish its result first.
        match self.commands.try_send(Command::Stop) {
            Ok(()) => {
                shared.status.phase = PfSessionPhase::Stopping;
                shared.status.last_stop = None;
                shared.closing = exit_after;
                self.updates.send_replace(shared.status);
                Ok(())
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                shared.status.phase = PfSessionPhase::Unavailable;
                self.updates.send_replace(shared.status);
                Err(ErrorCode::PfOperationUnavailable)
            }
        }
    }

    fn interrupt(&self) -> Result<InterruptOutcome, ErrorCode> {
        let mut shared = self
            .shared
            .lock()
            .map_err(|_| ErrorCode::PfOperationUnavailable)?;
        if shared.closing {
            return Err(ErrorCode::ServiceShuttingDown);
        }
        match shared.status.phase {
            PfSessionPhase::Starting => {
                shared.closing = true;
                Ok(InterruptOutcome::AwaitStartup)
            }
            PfSessionPhase::Stopping => {
                shared.closing = true;
                Ok(InterruptOutcome::AwaitStop)
            }
            PfSessionPhase::Stopped
            | PfSessionPhase::StartupInterrupted
            | PfSessionPhase::StartupFailed => {
                shared.closing = true;
                Ok(InterruptOutcome::Exit)
            }
            PfSessionPhase::Attached
            | PfSessionPhase::Detached
            | PfSessionPhase::Cleared
            | PfSessionPhase::Retiring => {
                self.enqueue_stop(&mut shared, true)?;
                Ok(InterruptOutcome::AwaitStop)
            }
            PfSessionPhase::DetachUnconfirmed
            | PfSessionPhase::ClearUnconfirmed
            | PfSessionPhase::ReleaseUnconfirmed => Err(ErrorCode::PfOperationUnconfirmed),
            PfSessionPhase::Unavailable => Err(ErrorCode::PfOperationUnavailable),
        }
    }

    fn stop_after_startup_interrupt(&self) -> Result<(), ErrorCode> {
        let mut shared = self
            .shared
            .lock()
            .map_err(|_| ErrorCode::PfOperationUnavailable)?;
        if !shared.closing || shared.status.phase != PfSessionPhase::Attached {
            return Err(ErrorCode::PfOperationUnavailable);
        }
        self.enqueue_stop(&mut shared, true)
    }

    fn start(&self) -> Result<Reply, ErrorCode> {
        let mut shared = self
            .shared
            .lock()
            .map_err(|_| ErrorCode::PfOperationUnavailable)?;
        if shared.closing {
            return Err(ErrorCode::ServiceShuttingDown);
        }
        match shared.status.phase {
            PfSessionPhase::Starting | PfSessionPhase::Stopping => {
                return Err(ErrorCode::PfOperationBusy);
            }
            PfSessionPhase::Attached => return Ok(Reply::PfAlreadyAttached {}),
            PfSessionPhase::DetachUnconfirmed
            | PfSessionPhase::ClearUnconfirmed
            | PfSessionPhase::ReleaseUnconfirmed => {
                return Err(ErrorCode::PfOperationUnconfirmed);
            }
            PfSessionPhase::Stopped => {}
            PfSessionPhase::Detached
            | PfSessionPhase::Cleared
            | PfSessionPhase::Retiring
            | PfSessionPhase::StartupInterrupted
            | PfSessionPhase::StartupFailed
            | PfSessionPhase::Unavailable => return Err(ErrorCode::PfOperationUnavailable),
        }
        // The previous live session is fully retired before a new start is admitted.
        match self.commands.try_send(Command::Start) {
            Ok(()) => {
                shared.status.phase = PfSessionPhase::Starting;
                shared.status.last_stop = None;
                self.updates.send_replace(shared.status);
                Ok(Reply::PfStartAccepted {})
            }
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                shared.status.phase = PfSessionPhase::Unavailable;
                self.updates.send_replace(shared.status);
                Err(ErrorCode::PfOperationUnavailable)
            }
        }
    }

    fn close(&self) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.closing = true;
        }
    }

    fn reopen(&self) {
        if let Ok(mut shared) = self.shared.lock() {
            shared.closing = false;
        }
    }
}

trait Engine: Send + 'static {
    fn start(&mut self) -> PfSessionPhase;
    fn stop(&mut self) -> (PfSessionPhase, PfStopOutcome);
    fn diagnose(&self) {}
}

enum HeldSession {
    None,
    Active(BlockingSession),
    // The live handle and record lock must stay held until the daemon exits.
    Interrupted(InterruptedSession),
}

struct NativeEngine {
    interface: String,
    session: HeldSession,
}

impl Engine for NativeEngine {
    fn start(&mut self) -> PfSessionPhase {
        // A stopped handle still owns the store lock. Drop it only after verified retirement,
        // then run all of the normal preflight and durable acquisition checks again.
        match &self.session {
            HeldSession::None => {}
            HeldSession::Active(session) if session.status() == SessionStatus::Stopped => {}
            HeldSession::Interrupted(_) => return PfSessionPhase::StartupInterrupted,
            HeldSession::Active(_) => return PfSessionPhase::Unavailable,
        }
        self.session = HeldSession::None;
        match BlockingSession::start(&self.interface) {
            Ok(session) => {
                self.session = HeldSession::Active(session);
                PfSessionPhase::Attached
            }
            Err(error) => {
                let (cause, interrupted) = error.into_parts();
                if let Some(interrupted) = interrupted {
                    tracing::error!(%cause, phase = ?interrupted.phase(), "PF startup interrupted; retaining session for diagnosis");
                    self.session = HeldSession::Interrupted(interrupted);
                    PfSessionPhase::StartupInterrupted
                } else {
                    tracing::error!(%cause, "PF startup failed; inspect records before another attempt");
                    PfSessionPhase::StartupFailed
                }
            }
        }
    }

    fn stop(&mut self) -> (PfSessionPhase, PfStopOutcome) {
        match &mut self.session {
            HeldSession::Active(session) => {
                let result = session.stop();
                if let Err(error) = &result {
                    tracing::error!(%error, phase = ?session.status(), "PF stop failed; session retained");
                }
                (
                    phase(session.status()),
                    if result.is_ok() {
                        PfStopOutcome::Completed
                    } else {
                        PfStopOutcome::Failed
                    },
                )
            }
            HeldSession::Interrupted(session) => {
                tracing::error!(phase = ?session.phase(), "interrupted startup cannot be stopped automatically");
                (PfSessionPhase::StartupInterrupted, PfStopOutcome::Failed)
            }
            HeldSession::None => (PfSessionPhase::Unavailable, PfStopOutcome::Failed),
        }
    }

    fn diagnose(&self) {
        let report = match &self.session {
            HeldSession::Active(session) => session.inspect(),
            HeldSession::Interrupted(session) => session.inspect(),
            HeldSession::None => return,
        };
        match report {
            Ok(report) => tracing::warn!(?report, "PF diagnostic; protection remains unknown"),
            Err(error) => tracing::warn!(%error, "PF diagnostic unavailable"),
        }
    }
}

fn phase(status: SessionStatus) -> PfSessionPhase {
    match status {
        SessionStatus::Attached => PfSessionPhase::Attached,
        SessionStatus::Detached => PfSessionPhase::Detached,
        SessionStatus::Cleared => PfSessionPhase::Cleared,
        SessionStatus::Retiring => PfSessionPhase::Retiring,
        SessionStatus::Unconfirmed(StopOperation::Detach) => PfSessionPhase::DetachUnconfirmed,
        SessionStatus::Unconfirmed(StopOperation::Clear) => PfSessionPhase::ClearUnconfirmed,
        SessionStatus::Unconfirmed(StopOperation::Release) => PfSessionPhase::ReleaseUnconfirmed,
        SessionStatus::Stopped => PfSessionPhase::Stopped,
    }
}

fn worker(mut engine: impl Engine, controller: Controller, queue: mpsc::Receiver<Command>) {
    let initial = engine.start();
    controller.publish(PfSessionStatus {
        actual_protection: PfProtection::Unknown,
        phase: initial,
        last_stop: None,
    });
    if initial == PfSessionPhase::StartupInterrupted {
        engine.diagnose();
    }
    while let Ok(command) = queue.recv() {
        match command {
            Command::Start => {
                let phase = engine.start();
                controller.publish(PfSessionStatus {
                    actual_protection: PfProtection::Unknown,
                    phase,
                    last_stop: None,
                });
                if phase == PfSessionPhase::StartupInterrupted {
                    engine.diagnose();
                }
            }
            Command::Stop => {
                let (phase, outcome) = engine.stop();
                controller.publish(PfSessionStatus {
                    actual_protection: PfProtection::Unknown,
                    phase,
                    last_stop: Some(outcome),
                });
                if outcome == PfStopOutcome::Failed {
                    engine.diagnose();
                }
            }
            Command::Exit => break,
        }
    }
    // Dropping either kind of retained session never submits a PF operation.
}

#[derive(Clone, Copy)]
enum Channel {
    Query,
    Control,
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    channel: Channel,
    controller: Controller,
) -> Result<(), IpcError> {
    let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    let request: RequestEnvelope = tokio::time::timeout_at(deadline, frame::read(&mut stream))
        .await
        .map_err(|_| IpcError::Timeout)??;
    if tokio::time::Instant::now() >= deadline {
        return Err(IpcError::Timeout);
    }
    let reply = if request.version != PROTOCOL_VERSION {
        Reply::Error {
            code: ErrorCode::UnsupportedVersion,
        }
    } else {
        match (channel, request.request) {
            (Channel::Query | Channel::Control, Request::PfSessionStatus {}) => {
                Reply::PfSessionStatus {
                    status: controller.status(),
                }
            }
            (Channel::Control, Request::PfStop {}) => controller
                .stop()
                .unwrap_or_else(|code| Reply::Error { code }),
            (Channel::Control, Request::PfStart {}) => controller
                .start()
                .unwrap_or_else(|code| Reply::Error { code }),
            _ => Reply::Error {
                code: ErrorCode::PfOperationUnavailable,
            },
        }
    };
    // A disconnected client or expired deadline cannot cancel the separately owned worker.
    tokio::time::timeout_at(
        deadline,
        frame::write(
            &mut stream,
            &ResponseEnvelope {
                version: PROTOCOL_VERSION,
                reply,
            },
        ),
    )
    .await
    .map_err(|_| IpcError::Timeout)??;
    Ok(())
}

pub(super) async fn run(interface: String, owner: NonZeroU32) -> anyhow::Result<()> {
    // Install signals and bind both verified endpoints before the first PF operation.
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let listeners = SystemListeners::bind(owner)
        .context("cannot bind system endpoints; PF startup was not attempted")?;
    let (controller, queue, mut changes) = Controller::new();
    let worker_controller = controller.clone();
    let mut worker = tokio::task::spawn_blocking(move || {
        worker(
            NativeEngine {
                interface,
                session: HeldSession::None,
            },
            worker_controller,
            queue,
        );
    });
    let mut clients = JoinSet::new();
    let mut interrupt_wait = None;
    let mut worker_finished = false;
    tracing::warn!("block-only PF session starting; protection remains unknown");
    let result: anyhow::Result<()> = loop {
        tokio::select! {
            result = &mut worker => {
                worker_finished = true;
                break Err(anyhow!("PF session worker exited unexpectedly: {result:?}"));
            }
            signal = terminate.recv() => {
                break signal.context("termination signal handler closed").map(|_| ());
            }
            signal = interrupt.recv() => {
                if signal.is_none() {
                    break Err(anyhow!("interrupt signal handler closed"));
                }
                match controller.interrupt() {
                    Ok(InterruptOutcome::AwaitStartup) => interrupt_wait = Some(InterruptOutcome::AwaitStartup),
                    Ok(InterruptOutcome::AwaitStop) => interrupt_wait = Some(InterruptOutcome::AwaitStop),
                    Ok(InterruptOutcome::Exit) => break Ok(()),
                    Err(code) => tracing::warn!(?code, "explicit SIGINT stop was not accepted"),
                }
            }
            changed = changes.changed() => {
                if changed.is_err() {
                    break Err(anyhow!("PF session status channel closed"));
                }
                let status = *changes.borrow_and_update();
                tracing::info!(phase = ?status.phase, last_stop = ?status.last_stop, "PF session checkpoint; protection remains unknown");
                match interrupt_wait {
                    Some(InterruptOutcome::AwaitStartup) => match status.phase {
                        PfSessionPhase::Starting => {},
                        PfSessionPhase::Attached => {
                            if let Err(code) = controller.stop_after_startup_interrupt() {
                                break Err(anyhow!("cannot request SIGINT stop after startup: {code:?}"));
                            }
                            interrupt_wait = Some(InterruptOutcome::AwaitStop);
                        },
                        PfSessionPhase::StartupInterrupted | PfSessionPhase::StartupFailed => break Ok(()),
                        _ => break Err(anyhow!("unexpected PF phase after interrupted startup")),
                    },
                    Some(InterruptOutcome::AwaitStop) => {
                        if status.phase == PfSessionPhase::Stopped {
                            break Ok(());
                        }
                        if status.phase != PfSessionPhase::Stopping {
                            interrupt_wait = None;
                            controller.reopen();
                        }
                    },
                    None => {},
                    Some(InterruptOutcome::Exit) => break Ok(()),
                }
            }
            result = clients.join_next(), if !clients.is_empty() => {
                match result {
                    Some(Ok(Ok(()))) | None => {},
                    Some(Ok(Err(error))) => tracing::debug!(%error, "system client exchange failed"),
                    Some(Err(error)) => break Err(error.into()),
                }
            }
            accepted = listeners.accept_query(), if clients.len() < MAX_CLIENTS => {
                match accepted {
                    Ok(stream) => { clients.spawn(handle(stream, Channel::Query, controller.clone())); },
                    Err(IpcError::Peer { .. }) => tracing::warn!("rejecting unauthorized system query peer"),
                    Err(error) => break Err(error.into()),
                }
            }
            accepted = listeners.accept_control(), if clients.len() < MAX_CLIENTS => {
                match accepted {
                    Ok(stream) => { clients.spawn(handle(stream, Channel::Control, controller.clone())); },
                    Err(IpcError::Peer { .. }) => tracing::warn!("rejecting unauthorized system control peer"),
                    Err(error) => break Err(error.into()),
                }
            }
        }
    };
    // Stop admission before waiting: a previously accepted stop may already be in flight.
    // SIGTERM itself never requests a PF write, and we wait for any in-flight native call.
    controller.close();
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    if !worker_finished {
        let commands = controller.commands.clone();
        let sent = tokio::task::spawn_blocking(move || commands.send(Command::Exit)).await;
        let finished = worker.await;
        finished?;
        sent??;
    }
    tracing::info!("PF session process exiting; protection remains unknown");
    result
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::sync::oneshot;

    use super::*;

    fn status(phase: PfSessionPhase, last_stop: Option<PfStopOutcome>) -> PfSessionStatus {
        PfSessionStatus {
            actual_protection: PfProtection::Unknown,
            phase,
            last_stop,
        }
    }

    #[test]
    fn stop_admission_never_queues_a_second_operation() -> anyhow::Result<()> {
        let (controller, queue, _changes) = Controller::new();
        assert!(matches!(controller.stop(), Err(ErrorCode::PfOperationBusy)));
        controller.publish(status(PfSessionPhase::Attached, None));
        assert!(matches!(controller.stop(), Ok(Reply::PfStopAccepted {})));
        assert!(matches!(controller.stop(), Err(ErrorCode::PfOperationBusy)));
        assert!(matches!(queue.try_recv()?, Command::Stop));
        assert!(matches!(queue.try_recv(), Err(mpsc::TryRecvError::Empty)));

        // A proved pre-submission failure needs a new, explicit request.
        controller.publish(status(
            PfSessionPhase::Attached,
            Some(PfStopOutcome::Failed),
        ));
        assert!(matches!(controller.stop(), Ok(Reply::PfStopAccepted {})));
        assert!(matches!(queue.try_recv()?, Command::Stop));
        controller.publish(status(
            PfSessionPhase::DetachUnconfirmed,
            Some(PfStopOutcome::Failed),
        ));
        assert!(matches!(
            controller.stop(),
            Err(ErrorCode::PfOperationUnconfirmed)
        ));
        assert!(matches!(queue.try_recv(), Err(mpsc::TryRecvError::Empty)));

        controller.publish(status(
            PfSessionPhase::Stopped,
            Some(PfStopOutcome::Completed),
        ));
        assert!(matches!(controller.stop(), Ok(Reply::PfAlreadyStopped {})));
        controller.close();
        assert!(matches!(
            controller.stop(),
            Err(ErrorCode::ServiceShuttingDown)
        ));
        Ok(())
    }

    #[test]
    fn failed_start_and_disconnected_worker_never_accept_stop() {
        let (controller, queue, _changes) = Controller::new();
        for phase in [
            PfSessionPhase::StartupInterrupted,
            PfSessionPhase::StartupFailed,
            PfSessionPhase::Unavailable,
        ] {
            controller.publish(status(phase, None));
            assert!(matches!(
                controller.stop(),
                Err(ErrorCode::PfOperationUnavailable)
            ));
        }
        drop(queue);
        controller.publish(status(PfSessionPhase::Attached, None));
        assert!(matches!(
            controller.stop(),
            Err(ErrorCode::PfOperationUnavailable)
        ));
        assert_eq!(controller.status().phase, PfSessionPhase::Unavailable);
    }

    #[test]
    fn start_requires_completed_stop_and_never_queues_implicit_retry() -> anyhow::Result<()> {
        let (controller, queue, _changes) = Controller::new();
        assert!(matches!(
            controller.start(),
            Err(ErrorCode::PfOperationBusy)
        ));
        controller.publish(status(PfSessionPhase::Attached, None));
        assert!(matches!(
            controller.start(),
            Ok(Reply::PfAlreadyAttached {})
        ));
        for phase in [
            PfSessionPhase::Detached,
            PfSessionPhase::Cleared,
            PfSessionPhase::Retiring,
            PfSessionPhase::StartupFailed,
            PfSessionPhase::StartupInterrupted,
        ] {
            controller.publish(status(phase, Some(PfStopOutcome::Failed)));
            assert!(matches!(
                controller.start(),
                Err(ErrorCode::PfOperationUnavailable)
            ));
        }
        for phase in [
            PfSessionPhase::DetachUnconfirmed,
            PfSessionPhase::ClearUnconfirmed,
            PfSessionPhase::ReleaseUnconfirmed,
        ] {
            controller.publish(status(phase, Some(PfStopOutcome::Failed)));
            assert!(matches!(
                controller.start(),
                Err(ErrorCode::PfOperationUnconfirmed)
            ));
        }
        controller.publish(status(
            PfSessionPhase::Stopped,
            Some(PfStopOutcome::Completed),
        ));
        assert!(matches!(controller.start(), Ok(Reply::PfStartAccepted {})));
        assert!(matches!(
            controller.start(),
            Err(ErrorCode::PfOperationBusy)
        ));
        assert!(matches!(controller.stop(), Err(ErrorCode::PfOperationBusy)));
        assert!(matches!(queue.try_recv()?, Command::Start));
        assert!(matches!(queue.try_recv(), Err(mpsc::TryRecvError::Empty)));
        Ok(())
    }

    #[test]
    fn signal_stop_closes_admission_until_failure_is_observed() -> anyhow::Result<()> {
        let (controller, queue, _changes) = Controller::new();
        controller.publish(status(PfSessionPhase::Attached, None));
        assert_eq!(controller.interrupt(), Ok(InterruptOutcome::AwaitStop));
        assert!(matches!(
            controller.start(),
            Err(ErrorCode::ServiceShuttingDown)
        ));
        assert!(matches!(queue.try_recv()?, Command::Stop));
        controller.publish(status(
            PfSessionPhase::Attached,
            Some(PfStopOutcome::Failed),
        ));
        controller.reopen();
        assert!(matches!(controller.stop(), Ok(Reply::PfStopAccepted {})));
        assert!(matches!(queue.try_recv()?, Command::Stop));
        Ok(())
    }

    #[test]
    fn interrupt_during_startup_waits_and_submits_exactly_one_stop() -> anyhow::Result<()> {
        let (controller, queue, _changes) = Controller::new();
        assert_eq!(controller.interrupt(), Ok(InterruptOutcome::AwaitStartup));
        assert!(matches!(
            controller.stop(),
            Err(ErrorCode::ServiceShuttingDown)
        ));
        assert!(matches!(queue.try_recv(), Err(mpsc::TryRecvError::Empty)));
        controller.publish(status(PfSessionPhase::Attached, None));
        assert_eq!(controller.stop_after_startup_interrupt(), Ok(()));
        assert!(matches!(queue.try_recv()?, Command::Stop));
        assert!(matches!(queue.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert!(matches!(
            controller.start(),
            Err(ErrorCode::ServiceShuttingDown)
        ));
        Ok(())
    }

    #[test]
    fn interrupt_joins_an_existing_stop_without_queuing_another() -> anyhow::Result<()> {
        let (controller, queue, _changes) = Controller::new();
        controller.publish(status(PfSessionPhase::Attached, None));
        assert!(matches!(controller.stop(), Ok(Reply::PfStopAccepted {})));
        assert_eq!(controller.interrupt(), Ok(InterruptOutcome::AwaitStop));
        assert!(matches!(queue.try_recv()?, Command::Stop));
        assert!(matches!(queue.try_recv(), Err(mpsc::TryRecvError::Empty)));
        assert!(matches!(
            controller.start(),
            Err(ErrorCode::ServiceShuttingDown)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn query_channel_rejects_stop_and_control_rejects_other_operations() -> anyhow::Result<()>
    {
        let (controller, queue, _changes) = Controller::new();
        controller.publish(status(PfSessionPhase::Attached, None));
        for (channel, request) in [
            (Channel::Query, Request::PfStop {}),
            (Channel::Query, Request::PfStart {}),
            (Channel::Control, Request::Status {}),
        ] {
            let (mut client, server) = tokio::io::duplex(1024);
            let server = tokio::spawn(handle(server, channel, controller.clone()));
            frame::write(
                &mut client,
                &RequestEnvelope {
                    version: PROTOCOL_VERSION,
                    request,
                },
            )
            .await?;
            let response: ResponseEnvelope = frame::read(&mut client).await?;
            assert!(matches!(
                response.reply,
                Reply::Error {
                    code: ErrorCode::PfOperationUnavailable
                }
            ));
            server.await??;
        }
        assert!(matches!(queue.try_recv(), Err(mpsc::TryRecvError::Empty)));
        Ok(())
    }

    #[tokio::test]
    async fn session_query_reports_local_phase_and_wrong_version_cannot_stop() -> anyhow::Result<()>
    {
        let (controller, queue, _changes) = Controller::new();
        let expected = status(PfSessionPhase::Attached, None);
        controller.publish(expected);
        for (channel, version, request) in [
            (
                Channel::Query,
                PROTOCOL_VERSION,
                Request::PfSessionStatus {},
            ),
            (Channel::Control, PROTOCOL_VERSION + 1, Request::PfStop {}),
        ] {
            let (mut client, server) = tokio::io::duplex(1024);
            let server = tokio::spawn(handle(server, channel, controller.clone()));
            frame::write(&mut client, &RequestEnvelope { version, request }).await?;
            let response: ResponseEnvelope = frame::read(&mut client).await?;
            if version == PROTOCOL_VERSION {
                assert!(
                    matches!(response.reply, Reply::PfSessionStatus { status } if status == expected)
                );
            } else {
                assert!(matches!(
                    response.reply,
                    Reply::Error {
                        code: ErrorCode::UnsupportedVersion
                    }
                ));
            }
            server.await??;
        }
        assert!(matches!(queue.try_recv(), Err(mpsc::TryRecvError::Empty)));
        Ok(())
    }

    struct BlockingEngine {
        calls: Arc<AtomicUsize>,
        started: Option<oneshot::Sender<()>>,
        finish: mpsc::Receiver<()>,
    }

    struct CycleEngine {
        starts: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
    }

    impl Engine for CycleEngine {
        fn start(&mut self) -> PfSessionPhase {
            self.starts.fetch_add(1, Ordering::SeqCst);
            PfSessionPhase::Attached
        }

        fn stop(&mut self) -> (PfSessionPhase, PfStopOutcome) {
            self.stops.fetch_add(1, Ordering::SeqCst);
            (PfSessionPhase::Stopped, PfStopOutcome::Completed)
        }
    }

    async fn wait_phase(
        changes: &mut watch::Receiver<PfSessionStatus>,
        phase: PfSessionPhase,
    ) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(2), async {
            while changes.borrow_and_update().phase != phase {
                changes.changed().await?;
            }
            Ok::<(), watch::error::RecvError>(())
        })
        .await??;
        Ok(())
    }

    #[tokio::test]
    async fn worker_serializes_stop_then_explicit_restart() -> anyhow::Result<()> {
        let (controller, queue, mut changes) = Controller::new();
        let starts = Arc::new(AtomicUsize::new(0));
        let stops = Arc::new(AtomicUsize::new(0));
        let engine = CycleEngine {
            starts: Arc::clone(&starts),
            stops: Arc::clone(&stops),
        };
        let worker_controller = controller.clone();
        let worker = tokio::task::spawn_blocking(move || worker(engine, worker_controller, queue));
        wait_phase(&mut changes, PfSessionPhase::Attached).await?;
        assert!(matches!(controller.stop(), Ok(Reply::PfStopAccepted {})));
        wait_phase(&mut changes, PfSessionPhase::Stopped).await?;
        assert!(matches!(controller.start(), Ok(Reply::PfStartAccepted {})));
        wait_phase(&mut changes, PfSessionPhase::Attached).await?;
        assert_eq!(starts.load(Ordering::SeqCst), 2);
        assert_eq!(stops.load(Ordering::SeqCst), 1);
        controller.close();
        controller.commands.send(Command::Exit)?;
        tokio::time::timeout(Duration::from_secs(2), worker).await??;
        Ok(())
    }

    impl Engine for BlockingEngine {
        fn start(&mut self) -> PfSessionPhase {
            PfSessionPhase::Attached
        }

        fn stop(&mut self) -> (PfSessionPhase, PfStopOutcome) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(started) = self.started.take() {
                let _ = started.send(());
            }
            if self.finish.recv().is_ok() {
                (PfSessionPhase::Stopped, PfStopOutcome::Completed)
            } else {
                (PfSessionPhase::DetachUnconfirmed, PfStopOutcome::Failed)
            }
        }
    }

    #[tokio::test]
    async fn disconnected_client_does_not_cancel_or_duplicate_started_stop() -> anyhow::Result<()> {
        let (controller, queue, mut changes) = Controller::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = oneshot::channel();
        let (finish_tx, finish_rx) = mpsc::channel();
        let engine = BlockingEngine {
            calls: Arc::clone(&calls),
            started: Some(started_tx),
            finish: finish_rx,
        };
        let worker_controller = controller.clone();
        let worker = tokio::task::spawn_blocking(move || worker(engine, worker_controller, queue));
        wait_phase(&mut changes, PfSessionPhase::Attached).await?;

        let (mut client, server) = tokio::io::duplex(1024);
        let server = tokio::spawn(handle(server, Channel::Control, controller.clone()));
        frame::write(
            &mut client,
            &RequestEnvelope {
                version: PROTOCOL_VERSION,
                request: Request::PfStop {},
            },
        )
        .await?;
        drop(client);
        // The response may fail, but the request was already admitted to the owner.
        let _ = server.await?;
        tokio::time::timeout(Duration::from_secs(2), started_rx).await??;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(controller.status().phase, PfSessionPhase::Stopping);
        assert!(matches!(controller.stop(), Err(ErrorCode::PfOperationBusy)));

        // Closing the service waits for the existing call; it does not submit another stop.
        controller.close();
        assert!(matches!(
            controller.stop(),
            Err(ErrorCode::ServiceShuttingDown)
        ));
        controller.commands.send(Command::Exit)?;
        finish_tx.send(())?;
        tokio::time::timeout(Duration::from_secs(2), worker).await??;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(controller.status().phase, PfSessionPhase::Stopped);
        Ok(())
    }
}
