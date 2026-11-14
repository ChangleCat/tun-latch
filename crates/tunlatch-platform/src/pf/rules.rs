//! Construction of a narrowly scoped PF block rule, without loading it into the kernel.
//!
//! This rule alone is not a protection policy. It does not establish interface identity,
//! anchor execution order, state convergence, or the exceptions needed for connectivity.

use pfctl::{Direction, DropAction, FilterRule, FilterRuleAction, FilterRuleBuilder, StatePolicy};

/// Error constructing an offline PF rule.
#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    /// The name is empty, too long for Darwin, or contains unsupported characters.
    #[error("invalid interface name")]
    InvalidInterface,
    /// The PF rule builder rejected the rule.
    #[error("could not build PF rule")]
    Build(#[source] pfctl::Error),
}

/// Construct a stateless outbound block rule for a named interface.
///
/// The name is checked for safe representation only; it is not evidence of an approved
/// physical interface. This function has no side effects and does not authorize installation.
pub fn outbound_block(interface: &str) -> Result<FilterRule, RuleError> {
    // Darwin IFNAMSIZ includes the terminating NUL. Avoid empty names (PF's any interface)
    // and accept only the conservative interface-name alphabet used by this product.
    if interface.is_empty()
        || interface.len() >= nix::libc::IFNAMSIZ
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(RuleError::InvalidInterface);
    }
    FilterRuleBuilder::default()
        .action(FilterRuleAction::Drop(DropAction::Drop))
        .direction(Direction::Out)
        .quick(true)
        .interface(interface)
        .keep_state(StatePolicy::None)
        .build()
        .map_err(RuleError::Build)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_names_that_cannot_safely_select_one_interface() {
        for name in ["", "abcdefghijklmnop", "en0\0", "en0/other", "en 0", "网卡"] {
            assert!(matches!(
                outbound_block(name),
                Err(RuleError::InvalidInterface)
            ));
        }
        assert!(outbound_block("en0").is_ok());
        assert!(outbound_block("abcdefghijklmno").is_ok());
    }

    #[test]
    fn selects_outbound_stateless_drop_on_the_requested_interface() -> Result<(), RuleError> {
        let actual = outbound_block("en0")?;
        let expected = FilterRuleBuilder::default()
            .action(FilterRuleAction::Drop(DropAction::Drop))
            .direction(Direction::Out)
            .quick(true)
            .interface("en0")
            .keep_state(StatePolicy::None)
            .build()
            .map_err(RuleError::Build)?;
        assert_eq!(actual, expected);
        assert_ne!(actual, outbound_block("en1")?);
        Ok(())
    }
}
