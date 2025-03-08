use pcsc::*;
use crate::*;
use crate::identification::{
    try_identify_card,
};

pub type PcscReaderName = std::ffi::CString;

#[derive(Debug)]
pub struct CardInfo {
    pub ident: CardIdent,
    pub pcsc_address: PcscReaderName,
}

pub struct Callbacks {
    pub card_available: Box<dyn Fn(&CardInfo) -> ()>,
    pub card_unavailable: Box<dyn Fn(&CardInfo) -> ()>,
}

// Based on https://github.com/bluetech/pcsc-rust/blob/master/pcsc/examples/monitor.rs

#[derive(Debug)]
pub struct MonitorLoopStarting();

pub fn start(callbacks: Option<Callbacks>) {
    let ctx = Context::establish(Scope::User).expect("failed to establish context");

    let mut readers_buf = [0; 2048];
    let mut reader_states = vec![
        // Listen for reader insertions/removals, if supported.
        ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE),
    ];
    loop {
        println!("{:?}", MonitorLoopStarting());
        // Remove dead readers.
        fn is_dead(rs: &ReaderState) -> bool {
            rs.event_state().intersects(State::UNKNOWN | State::IGNORE)
        }
        for rs in &reader_states {
            if is_dead(rs) && rs.name() != PNP_NOTIFICATION() {
                let card_info = CardInfo {
                    ident: "not yet persisted".to_string(),  // TODO
                    pcsc_address: rs.name().to_owned(),
                };
                callbacks.as_ref().map(|c| (c.card_unavailable)(&card_info));
            }
        }
        reader_states.retain(|rs| !is_dead(rs));

        // Add new readers.
        let names = ctx.list_readers(&mut readers_buf).expect("failed to list readers");
        for name in names {
            if !reader_states.iter().any(|rs| rs.name() == name) {
                reader_states.push(ReaderState::new(name, State::UNAWARE));
                let ident = try_identify_card(&ctx, &name).expect("ident");
                let card_info = CardInfo {
                    ident: ident,
                    pcsc_address: name.to_owned(),
                };
                callbacks.as_ref().map(|c| (c.card_available)(&card_info));
            }
        }

        // Update the view of the state to wait on.
        for rs in &mut reader_states {
            rs.sync_current_state();
        }

        // Wait until the state changes.
        ctx.get_status_change(None, &mut reader_states)
            .expect("failed to get status change");

        // Print current state.
        for rs in &reader_states {
            if rs.name() != PNP_NOTIFICATION() {
                //println!("{:?} {:?} {:02x?}", rs.name(), rs.event_state(), rs.atr());
            }
        }
    }
}
