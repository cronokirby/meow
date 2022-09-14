// The basic idea of this module is to perform a kind of fuzz testing of our implementation.
// This testing works by generating a random transcript of commands, and then
// simulating a protocol execution between two parties.
// This allows us to exercise some basic properties, like that the parties
// should agree on what's being communicated, and their states should be synchronized,
// but also more complicated things, like it being impossible to generate two transcripts
// which create a "collision" in terms of their hash outputs.
use crate::meow::Meow;
use proptest::{collection::vec, prelude::*};

/// Represents a single command in the protocol.
///
/// Each command basically represents an operation we can do with our instance.
#[derive(Clone, Debug, PartialEq)]
enum Command {
    /// Add additional data into the state.
    Ad(Vec<u8>),
    /// Send a plaintext message to the other party.
    Clr(bool, Vec<u8>),
    /// Send an encrypted message to the other party.
    Enc(bool, Vec<u8>),
    /// Generate some bytes of random output.
    Prf(usize),
    /// Send a MAC of a certain length to the other party.
    Mac(usize),
    Ratchet,
}

/// Represents a full protocol transcript.
#[derive(Clone, Debug, PartialEq)]
struct Commands {
    /// The protocol string.
    protocol: Vec<u8>,
    /// A list of commands.
    commands: Vec<Command>,
}

/// Simulate a protocol execution, given a transcript of commands.
///
/// We do this by setting up two Meow states, with each command updating the states.
/// In essence, the sequence of commands determines a protocol where two parties
/// communicate together, and use the PRF commands to generate random output.
///
/// This simulation verifies that the communication is consistent, via assertions,
/// and then returns the PRF output generated throughout the protocol.
fn run_and_assert_commands(commands: &Commands) -> Vec<u8> {
    let mut prf_out = Vec::new();
    let mut prf_pos = 0;

    let mut meow0 = Meow::new(&commands.protocol);
    let mut meow1 = Meow::new(&commands.protocol);

    let mut scratch = Vec::new();

    for command in &commands.commands {
        match command {
            Command::Ad(data) => {
                meow0.ad(data, false);
                meow1.ad(data, false);
            }
            Command::Clr(swap, plaintext) => {
                if *swap {
                    meow0.send_clr(plaintext, false);
                    meow1.recv_clr(plaintext, false);
                } else {
                    meow1.send_clr(plaintext, false);
                    meow0.recv_clr(plaintext, false);
                }
            }
            Command::Enc(swap, plaintext) => {
                let mut ciphertext = plaintext.clone();
                if *swap {
                    meow0.send_enc(&mut ciphertext, false);
                    meow1.recv_enc(&mut ciphertext, false);
                } else {
                    meow1.send_enc(&mut ciphertext, false);
                    meow0.recv_enc(&mut ciphertext, false);
                }
                assert_eq!(&ciphertext, plaintext);
            }
            // Add the PRF result to the output, and check that both states agree.
            Command::Prf(len) => {
                scratch.resize(*len, 0);
                meow0.prf(&mut scratch, false);
                prf_out.extend_from_slice(&scratch);
                meow1.prf(&mut scratch, false);
                assert_eq!(&scratch, &prf_out[prf_pos..prf_pos + *len]);
                prf_pos += len;
                scratch.clear();
            }
            Command::Mac(len) => {
                scratch.resize(*len, 0);
                meow0.send_mac(&mut scratch);
                assert!(meow1.recv_mac(&mut scratch).is_ok())
            }
            Command::Ratchet => {
                meow0.ratchet();
                meow1.ratchet();
            }
        }
    }

    prf_out
}

fn arb_data() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..200)
}

prop_compose! {
    fn arb_bool_and_data()(switch in any::<bool>(), data in arb_data()) -> (bool, Vec<u8>) {
        (switch, data)
    }
}

fn arb_command() -> impl Strategy<Value = Command> {
    use Command::*;

    prop_oneof![
        arb_data().prop_map(Ad),
        arb_bool_and_data().prop_map(|(s, d)| Clr(s, d)),
        arb_bool_and_data().prop_map(|(s, d)| Enc(s, d)),
        Just(Prf(32)),
        Just(Mac(32)),
        Just(Ratchet),
    ]
}

prop_compose! {
    fn arb_commands()(protocol in arb_data(), commands in vec(arb_command(), 0..32)) -> Commands {
        Commands { protocol, commands }
    }
}

proptest! {
    #[test]
    fn test_commands(c0 in arb_commands(), c1 in arb_commands()) {
        let out0 = run_and_assert_commands(&c0);
        let out1 = run_and_assert_commands(&c1);
        // Either the commands should be the same, and then the output matches,
        // or they should be different, and the output should be different too.
        if c0 == c1 {
            assert_eq!(out0, out1);
        } else if !(out0.is_empty() && out1.is_empty()) {
            assert_ne!(out0, out1);
        }
    }
}
