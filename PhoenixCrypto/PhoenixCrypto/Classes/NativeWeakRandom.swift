import Foundation
import CryptoKit
import os.log

fileprivate var log = Logger(
	subsystem: Bundle.main.bundleIdentifier!,
	category: "NativeWeakRandom"
)

@objc
public class NativeWeakRandom: NSObject {

    @objc
    private class func toByteArr(i: UInt64) -> [UInt8] {
        let count = MemoryLayout<UInt64>.size
        var _i = i
        return withUnsafePointer(to: &_i) {
          $0.withMemoryRebound(to: UInt8.self, capacity: count) {
            [UInt8](UnsafeBufferPointer(start: $0, count: count))
          }
        }
    }

	@objc
	public class func sample() -> Data {

	    // Sample some entropy from the running process metrics.
		let pid = UInt64(getpid())
		let usage = rusage_info_current()
		var entropy : [UInt8] = toByteArr(i: pid)
		entropy += toByteArr(i: usage.ri_user_time)
		entropy += toByteArr(i: usage.ri_system_time)
		entropy += toByteArr(i: usage.ri_pkg_idle_wkups)
		entropy += toByteArr(i: usage.ri_interrupt_wkups)
		entropy += toByteArr(i: usage.ri_pageins)
		entropy += toByteArr(i: usage.ri_wired_size)
		entropy += toByteArr(i: usage.ri_resident_size)
		entropy += toByteArr(i: usage.ri_phys_footprint)
		entropy += toByteArr(i: usage.ri_proc_start_abstime)
		entropy += toByteArr(i: usage.ri_proc_exit_abstime)
		entropy += toByteArr(i: usage.ri_child_user_time)
		entropy += toByteArr(i: usage.ri_child_system_time)
		entropy += toByteArr(i: usage.ri_child_pkg_idle_wkups)
		entropy += toByteArr(i: usage.ri_child_interrupt_wkups)
		entropy += toByteArr(i: usage.ri_child_pageins)
		entropy += toByteArr(i: usage.ri_child_elapsed_abstime)
		entropy += toByteArr(i: usage.ri_diskio_bytesread)
		entropy += toByteArr(i: usage.ri_diskio_byteswritten)
		entropy += toByteArr(i: usage.ri_cpu_time_qos_default)
		entropy += toByteArr(i: usage.ri_cpu_time_qos_maintenance)
		entropy += toByteArr(i: usage.ri_cpu_time_qos_background)
		entropy += toByteArr(i: usage.ri_cpu_time_qos_utility)
		entropy += toByteArr(i: usage.ri_cpu_time_qos_legacy)
		entropy += toByteArr(i: usage.ri_cpu_time_qos_user_initiated)
		entropy += toByteArr(i: usage.ri_cpu_time_qos_user_interactive)
		entropy += toByteArr(i: usage.ri_billed_system_time)
		entropy += toByteArr(i: usage.ri_serviced_system_time)
		entropy += toByteArr(i: usage.ri_logical_writes)
		entropy += toByteArr(i: usage.ri_lifetime_max_phys_footprint)
		entropy += toByteArr(i: usage.ri_instructions)
		entropy += toByteArr(i: usage.ri_cycles)
		entropy += toByteArr(i: usage.ri_billed_energy)
		entropy += toByteArr(i: usage.ri_serviced_energy)
		entropy += toByteArr(i: usage.ri_interval_max_phys_footprint)
		entropy += toByteArr(i: usage.ri_runnable_time)

		return Data(entropy)
	}
}
