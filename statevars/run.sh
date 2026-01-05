#!/usr/bin/env bash
set -euo pipefail

# Directory of this script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Python module name (statevars.py -> statevars)
MODULE="analysis"

# Python executable (override with: PYTHON=/path/to/python ./run_statevars.sh ...)
PYTHON="${PYTHON:-python}"

# Logs directory (same as in your Python code)
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "${LOG_DIR}"

run_one_py() {
    local binary="$1"
    local funcs_expr="$2"   # Python expression for funcs list, e.g. [0x42C034] or ["loop"]
    local outfile="$3"

    "${PYTHON}" -c "from ${MODULE} import run_one; run_one(\"${binary}\", ${funcs_expr}, out_file=\"${LOG_DIR}/${outfile}\")"
}

traffic_tl9() {
    echo "Running Traffic light (beremiz)..."
    run_one_py \
        "../artifacts/Traffic_Light_original/build/Traffic_Light_original.so" \
        "[0x42C034]" \
        "traffic-light-tl9.out"
}

water_tank_2() {
    echo "Running water tank..."
    run_one_py \
        "../artifacts/water_tank_sfc_one_sensor/build/water_tank_sfc_one_sensor.so" \
        "[0x4235C9]" \
        "water-tank_2.out"
}

water_tank_fbd() {
    echo "Running water tank fbd..."
    run_one_py \
        "../artifacts/water_tank/build/water_tank.so" \
        "[0x41C24A]" \
        "water-tank-fbd_1.out"
}

warehouse_lifter() {
    echo "Running lifter..."
    run_one_py \
        "../artifacts/warehouse_lift/build/warehouse_lift.so" \
        "[0x423A54]" \
        "warehouse-lifter.out"
}

water_tank_wt3() {
    echo "Running water tank (WT.3)..."
    run_one_py \
        "../artifacts/water_tank_sfc_two_sesnors/build/water_tank_sfc_two_sesnors.so" \
        "[0x436870]" \
        "water-tank-wt3.out"
}

packaging() {
    echo "Running Packaging..."
    run_one_py \
        "../artifacts/packaging_sfc/build/packaging_sfc.so" \
        "[0x4236C0]" \
        "packaging.out"
}

packaging_mips() {
    echo "Running Packaging MIPS..."
    run_one_py \
        "../artifacts/packaging_sfc/build/packaging_sfc_mips.so" \
        "[0x416634]" \
        "packaging-mips.out"
}

packaging_ppc32() {
    echo "Running Packaging PPC32..."
    run_one_py \
        "../artifacts/packaging_sfc/build/packaging_sfc_powerpc.so" \
        "[0x41689c]" \
        "packaging-ppc32.out"
}

traffic_tl4() {
    echo "Running traffic light (TL.4)..."
    run_one_py \
        "../artifacts/traffic_light_addsensor_x86-64/Traffic_Light_addsensor_x86-64.so" \
        "[0x42C83D]" \
        "traffic-light-tl4.out"
}

traffic_tl5() {
    echo "Running traffic light (TL.5)..."
    run_one_py \
        "../artifacts/Traffic_Light_Short_Ped_5/build/Traffic_Light_Short_Ped.so" \
        "[0x42BF53]" \
        "traffic-light-tl5.out"
}

traffic_tl6() {
    echo "Running traffic light (TL.6)..."
    run_one_py \
        "../artifacts/Traffic_Light_Short_Ped_6/build/Traffic_Light_Short_Ped.so" \
        "[0x42C698]" \
        "traffic-light-tl6.out"
}

traffic_tl7() {
    echo "Running traffic light (TL.7)..."
    run_one_py \
        "../artifacts/Traffic_Light_both_green_7/build/Traffic_Light_both_green.so" \
        "[0x42BF53]" \
        "traffic-light-tl7.out"
}

traffic_tl8() {
    echo "Running traffic light (TL.8)..."
    run_one_py \
        "../artifacts/Traffic_Light_short_orange/build/Traffic_Light_short_orange.so" \
        "[0x42BF53]" \
        "traffic-light-tl8.out"
}

traffic_tl10() {
    echo "Running traffic light (TL.10)..."
    run_one_py \
        "../artifacts/Traffic_Light_10/build/Traffic_Light.so" \
        "[0x42C698]" \
        "traffic-light-tl10.out"
}

traffic_tl11() {
    echo "Running traffic light (TL.11)..."
    run_one_py \
        "../artifacts/traffic_light_simulink/MyBlinky.elf" \
        '["MyBlinky_step"]' \
        "traffic-light-tl11.out"
}

launch_abort() {
    echo "Running abort system (Abort.1)..."
    run_one_py \
        "../artifacts/binaries/sf_launchabort.exe" \
        "[0x4015CD]" \
        "launch-abort-system-abort1.out"
}

oven_oven1() {
    echo "Running Oven (Oven.1)..."
    run_one_py \
        "../artifacts/oven/oven.ino.elf" \
        '["loop"]' \
        "oven-oven1.out"
}

vending_vend1() {
    echo "Running Vending Machine (Vend.1)..."
    run_one_py \
        "../artifacts/vending_machine/arduino_build_389120/vending_machine.ino.elf" \
        '["_Z14vendingMachinev"]' \
        "vending-vend1.out"
}

elevator_elev1() {
    echo "Running Elevator (Elev.1)..."
    run_one_py \
        "../artifacts/elevator/elevator.ino.elf" \
        '["loop"]' \
        "elevator-elev1.out"
}

carwash_carw1() {
    echo "Running Car Wash (CarW.1)..."
    run_one_py \
        "../artifacts/car_wash/build/car_wash.so" \
        "[0x438395]" \
        "car-wash.out"
}

carwash_carw2_arm() {
    echo "Running Car Wash (CarW.2) ARM..."
    run_one_py \
        "../artifacts/car_wash/build/carwash-mkr1010.elf" \
        "[0x2da5]" \
        "car-wash-arm.out"
}

run_all() {
    traffic_tl9
    water_tank_2
    water_tank_fbd
    warehouse_lifter
    water_tank_wt3
    packaging
    packaging_mips
    packaging_ppc32
    traffic_tl4
    traffic_tl5
    traffic_tl6
    traffic_tl7
    traffic_tl8
    traffic_tl10
    traffic_tl11
    launch_abort
    oven_oven1
    vending_vend1
    elevator_elev1
    carwash_carw1
    carwash_carw2_arm
}

usage() {
    cat <<EOF
Usage: $0 <target>

Targets:
  traffic-tl9
  water-tank
  water-tank-fbd
  warehouse-lifter
  water-tank-wt3
  packaging
  packaging-mips
  packaging-ppc32
  traffic-tl4
  traffic-tl5
  traffic-tl6
  traffic-tl7
  traffic-tl8
  traffic-tl10
  traffic-tl11
  launch-abort
  oven-oven1
  vending-vend1
  elevator-elev1
  carwash-carw1
  carwash-carw2-arm
  all

Example:
  $0 water-tank
  $0 traffic-tl4
  $0 all
EOF
}

main() {
    local target="${1:-}"

    case "${target}" in
        traffic_tl9)     traffic_tl9      ;;
        water-tank)          water_tank           ;;
        water-tank-fbd)      water_tank_fbd       ;;
        warehouse-lifter)    warehouse_lifter     ;;
        water-tank-wt3)      water_tank_wt3       ;;
        packaging)           packaging            ;;
        packaging-mips)      packaging_mips       ;;
        packaging-ppc32)     packaging_ppc32      ;;
        traffic-tl4)         traffic_tl4          ;;
        traffic-tl5)         traffic_tl5          ;;
        traffic-tl6)         traffic_tl6          ;;
        traffic-tl7)         traffic_tl7          ;;
        traffic-tl8)         traffic_tl8          ;;
        traffic-tl10)        traffic_tl10         ;;
        traffic-tl11)        traffic_tl11         ;;
        launch-abort)        launch_abort         ;;
        oven-oven1)          oven_oven1           ;;
        vending-vend1)       vending_vend1        ;;
        elevator-elev1)      elevator_elev1       ;;
        carwash-carw1)       carwash_carw1        ;;
        carwash-carw2-arm)   carwash_carw2_arm    ;;
        all)                 run_all              ;;
        ""|help|-h|--help)   usage; exit 0        ;;
        *)                   usage; exit 1        ;;
    esac
}

main "$@"
