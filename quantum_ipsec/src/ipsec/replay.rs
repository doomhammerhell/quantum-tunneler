use crate::{QuantumIpsecError as Error, Result};
/// 64-packet sliding window; only authenticated packets may advance it.
#[derive(Debug, Default)]
pub struct ReplayWindow {
    highest: u32,
    bitmap: u64,
}
impl ReplayWindow {
    pub fn check(&self, sequence: u32) -> Result<()> {
        if sequence == 0 {
            return Err(Error::Replay);
        }
        if sequence > self.highest {
            return Ok(());
        }
        let delta = self.highest - sequence;
        if delta >= 64 || self.bitmap & (1u64 << delta) != 0 {
            return Err(Error::Replay);
        }
        Ok(())
    }
    pub(crate) fn commit(&mut self, sequence: u32) -> Result<()> {
        self.check(sequence)?;
        if sequence > self.highest {
            let shift = sequence - self.highest;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.highest = sequence;
        } else {
            self.bitmap |= 1u64 << (self.highest - sequence);
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn edges() {
        let mut w = ReplayWindow::default();
        assert!(w.check(0).is_err());
        w.commit(100).unwrap();
        w.commit(37).unwrap();
        assert!(w.check(36).is_err());
        assert!(w.check(37).is_err());
        w.commit(99).unwrap();
        w.commit(164).unwrap();
        assert!(w.check(100).is_err());
        w.commit(u32::MAX).unwrap();
        assert!(w.check(u32::MAX).is_err());
    }
}
