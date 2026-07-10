# Cycle-correct NetPulse

`netpulse_live.py` is a cycle-aware companion entry point for NetPulse.

nethogs trace mode emits one row per process and separates sampling rounds with
`Refreshing:`. The original GUI treated each row as a graph point and retained a
process's last rate until another row replaced it. That can make aggregate live
rates include exited processes and makes the graph connect unrelated process
rows as though they were successive whole-system observations.

The cycle-aware command waits for a completed nethogs round before it:

- writes aggregated per-process samples to history;
- evaluates alert streaks once per completed cycle;
- updates current process rates;
- zeros processes absent from the new round;
- adds one whole-system upload/download point to the graph;
- accounts for normal sampling jitter without counting suspend/resume gaps as
  hours of fictional traffic;
- separates a recycled PID from an unrelated application that later receives it.

Run it exactly like the original command:

```bash
./netpulse_live.py --gui
./netpulse_live.py --gui --up-kb 8 --down-kb 32 --graph-minutes 30
./netpulse_live.py --verbose
```

The existing `netpulse.py` remains available unchanged. `install.sh` installs
both `netpulse` and `netpulse-live`, making comparison and rollback trivial.
