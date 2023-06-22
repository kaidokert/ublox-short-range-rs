#![allow(dead_code)]

use core::cell::RefCell;
use core::mem::MaybeUninit;
use core::task::Context;

use atat::asynch::AtatClient;
use atat::UrcSubscription;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::blocking_mutex::Mutex;
use embassy_sync::waitqueue::WakerRegistration;

use crate::command::edm::urc::EdmEvent;

/// The link state of a network device.
#[derive(PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LinkState {
    /// The link is down.
    Down,
    /// The link is up.
    Up,
}

use super::AtHandle;

pub struct State {
    inner: MaybeUninit<StateInner>,
}

impl State {
    pub const fn new() -> Self {
        Self {
            inner: MaybeUninit::uninit(),
        }
    }
}

struct StateInner {
    shared: Mutex<NoopRawMutex, RefCell<Shared>>,
}

/// State of the LinkState
struct Shared {
    link_state: LinkState,
    waker: WakerRegistration,
}

pub struct Runner<'d> {
    shared: &'d Mutex<NoopRawMutex, RefCell<Shared>>,
}

#[derive(Clone, Copy)]
pub struct StateRunner<'d> {
    shared: &'d Mutex<NoopRawMutex, RefCell<Shared>>,
}

impl<'d> Runner<'d> {
    pub fn state_runner(&self) -> StateRunner<'d> {
        StateRunner {
            shared: self.shared,
        }
    }

    pub fn set_link_state(&mut self, state: LinkState) {
        self.shared.lock(|s| {
            let s = &mut *s.borrow_mut();
            s.link_state = state;
            s.waker.wake();
        });
    }
}

impl<'d> StateRunner<'d> {
    pub fn set_link_state(&self, state: LinkState) {
        self.shared.lock(|s| {
            let s = &mut *s.borrow_mut();
            s.link_state = state;
            s.waker.wake();
        });
    }

    pub fn link_state(&mut self, cx: &mut Context) -> LinkState {
        self.shared.lock(|s| {
            let s = &mut *s.borrow_mut();
            s.waker.register(cx.waker());
            s.link_state
        })
    }
}

pub fn new<'d, AT: AtatClient>(
    state: &'d mut State,
    at: AtHandle<'d, AT>,
    urc_subscription: UrcSubscription<'d, EdmEvent>,
) -> (Runner<'d>, Device<'d, AT>) {
    // safety: this is a self-referential struct, however:
    // - it can't move while the `'d` borrow is active.
    // - when the borrow ends, the dangling references inside the MaybeUninit will never be used again.
    let state_uninit: *mut MaybeUninit<StateInner> =
        (&mut state.inner as *mut MaybeUninit<StateInner>).cast();

    let state = unsafe { &mut *state_uninit }.write(StateInner {
        shared: Mutex::new(RefCell::new(Shared {
            link_state: LinkState::Down,
            waker: WakerRegistration::new(),
        })),
    });

    (
        Runner {
            shared: &state.shared,
        },
        Device {
            shared: &state.shared,
            urc_subscription,
            at,
        },
    )
}

pub struct Device<'d, AT: AtatClient> {
    pub(crate) shared: &'d Mutex<NoopRawMutex, RefCell<Shared>>,
    pub(crate) at: AtHandle<'d, AT>,
    pub(crate) urc_subscription: UrcSubscription<'d, EdmEvent>,
}

impl<'d, AT: AtatClient> Device<'d, AT> {
    pub fn link_state(&self, cx: &mut Context) -> LinkState {
        self.shared.lock(|s| {
            let s = &mut *s.borrow_mut();
            s.waker.register(cx.waker());
            s.link_state
        })
    }
}
