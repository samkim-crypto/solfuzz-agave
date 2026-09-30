use serde::Serialize;
use std::time::Instant;

#[derive(Clone, Debug, Serialize)]
pub struct Sample {
    pub wall_ns: u64,
    pub thread_cpu_ns: u64,
    pub voluntary_switches: i64,
    pub involuntary_switches: i64,
    pub charged_cu: u64,
}

fn cpu_ns() -> u64 {
    let mut t = std::mem::MaybeUninit::<libc::timespec>::uninit();
    assert_eq!(
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, t.as_mut_ptr()) },
        0
    );
    let t = unsafe { t.assume_init() };
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}

fn usage() -> libc::rusage {
    let mut u = std::mem::MaybeUninit::<libc::rusage>::uninit();
    assert_eq!(
        unsafe { libc::getrusage(libc::RUSAGE_THREAD, u.as_mut_ptr()) },
        0
    );
    unsafe { u.assume_init() }
}

pub struct Timer {
    usage: libc::rusage,
    cpu_ns: u64,
    wall: Instant,
}
impl Timer {
    pub fn start() -> Self {
        Self {
            usage: usage(),
            cpu_ns: cpu_ns(),
            wall: Instant::now(),
        }
    }
    pub fn finish(self) -> Sample {
        let wall_ns = self.wall.elapsed().as_nanos().try_into().unwrap();
        let thread_cpu_ns = cpu_ns() - self.cpu_ns;
        let after = usage();
        Sample {
            wall_ns,
            thread_cpu_ns,
            voluntary_switches: after.ru_nvcsw - self.usage.ru_nvcsw,
            involuntary_switches: after.ru_nivcsw - self.usage.ru_nivcsw,
            charged_cu: 0,
        }
    }
}

pub fn pin(cpu: usize) -> Result<(), String> {
    if cpu >= libc::CPU_SETSIZE as usize {
        return Err("CPU index exceeds CPU_SETSIZE".into());
    }
    let mut allowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&allowed), &mut allowed) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if !unsafe { libc::CPU_ISSET(cpu, &allowed) } {
        return Err(format!("CPU {cpu} is not in the allowed affinity mask"));
    }
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::CPU_SET(cpu, &mut set);
    }
    if unsafe { libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(())
}
