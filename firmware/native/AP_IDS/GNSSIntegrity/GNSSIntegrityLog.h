/*
 * DataFlash detail records for the GNSSIntegrity engine (SPIDERS FW-13).
 *
 * These are NEW records, not existing ArduPilot messages. The GCS parser
 * (backend/app/ids/pushpak_fc.py) and its contract tests
 * (backend/tests/test_firmware_contract.py) pin exactly these names, formats
 * and labels. Change both sides together and bump kIDSGVersion.
 *
 * ArduPilot's FMT record limits a format to 16 characters and the label list to
 * 64 bytes, so the per-horizon detail is split out of IDSG into one IDSR row per
 * horizon. IDSR rows for a given Seq are written BEFORE the IDSG summary with
 * the same Seq. Rate: 1 Hz plus every state transition; never per IMU sample.
 *
 * IDSG  QIIBBBBBBIHhffff
 *   TimeUS  Q  FC monotonic time (us)
 *   Boot    I  AP_IDS boot id (FW-06; 0 until implemented)
 *   Seq     I  evaluation sequence (shared with IDSR)
 *   Ver     B  record version (kIDSGVersion)
 *   St      B  GNSSInt::State (0 DISABLED .. 7 ALARM)
 *   AM      B  armed (active) horizon mask, bit i = horizon i (2,5,15,30,60 s)
 *   VM      B  valid horizon mask
 *   WM      B  warning horizon mask
 *   XM      B  alarm horizon mask
 *   Fl      I  GNSSInt::ResultFlag bits
 *   FAge    H  GNSS message time - fix time (ms)
 *   Lag     h  latency compensation applied by the engine (ms)
 *   Conf    f  r/(1+r), r = joint max statistic / alarm threshold
 *   DvR     f  heading-free speed-change residual (m/s) of the worst horizon
 *   BrR     f  baro altitude-change residual (m) of the worst horizon
 *   BiN     f  accelerometer bias estimate norm (m/s/s)
 *
 * IDSR  QIIBBBBfffffffff   (one row per horizon, H = 0..4)
 *   TimeUS, Boot, Seq, H (index), Dur (s), St (HorizonStatusBit), Rsn (HorizonReason),
 *   El (elapsed s), RP (|pos residual| m), RV (|vel residual| m/s),
 *   TP, TV, TD (pos / vel / speed-change test statistics),
 *   SP (pos sigma m), SV (vel sigma m/s), YSd (yaw sigma rad)
 */
#pragma once

#include <stdint.h>

namespace GNSSInt {

static const uint8_t kIDSGVersion = 1;

#define GNSSINT_IDSG_NAME   "IDSG"
#define GNSSINT_IDSG_LABELS "TimeUS,Boot,Seq,Ver,St,AM,VM,WM,XM,Fl,FAge,Lag,Conf,DvR,BrR,BiN"
#define GNSSINT_IDSG_FORMAT "QIIBBBBBBIHhffff"

#define GNSSINT_IDSR_NAME   "IDSR"
#define GNSSINT_IDSR_LABELS "TimeUS,Boot,Seq,H,Dur,St,Rsn,El,RP,RV,TP,TV,TD,SP,SV,YSd"
#define GNSSINT_IDSR_FORMAT "QIIBBBBfffffffff"

// Evidence bits the native GPS detector adds to its PIDS / IDSE summary when the
// physics engine contributes (must match EVIDENCE_BITS in backend/app/mavlink/pushpak.py
// and stay clear of the Lua EVID_* constants in firmware/scripts/modules/ids_common.lua).
static const uint16_t kEvidenceInsPrediction = 4096;   // INS_PREDICTION: horizon vector / speed-change test
static const uint16_t kEvidencePhysConstraint = 8192;  // PHYS_CONSTRAINT: baro / stationary-ground test

} // namespace GNSSInt
