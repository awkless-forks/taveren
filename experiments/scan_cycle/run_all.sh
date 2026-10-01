#!/bin/bash

cd "$(dirname "${BASH_SOURCE[0]}")"

# Create output directory
outdir="outputs"
mkdir -p "$outdir"

run_cmd () {
    cmd="$1"
    filepath="$2"

    filename=$(basename "$filepath")
    outfile="$outdir/${filename}.txt"

    echo "Running: $cmd"
    eval "$cmd" &> "$outfile"
    echo " → Output saved to $outfile"
}

# ---- Commands ----

run_cmd "taveren-scan-cycle ../../tests/fixtures/packaging_sfc/build/packaging_sfc.so" \
        "packaging_sfc.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/packaging_sfc/build/packaging_sfc_mips.so" \
        "packaging_sfc_mips.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/packaging_sfc/build/packaging_sfc_powerpc.so" \
        "packaging_sfc_powerpc.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/traffic_light_addsensor_x86-64/Traffic_Light_addsensor_x86-64.so" \
        "Traffic_Light_addsensor_x86-64_4.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/Traffic_Light_Short_Ped_5/build/Traffic_Light_Short_Ped.so" \
        "Traffic_Light_Short_Ped_5.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/Traffic_Light_Short_Ped_6/build/Traffic_Light_Short_Ped.so" \
        "Traffic_Light_Short_Ped_6.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/Traffic_Light_both_green_7/build/Traffic_Light_both_green.so" \
        "Traffic_Light_both_green_7.so" &


run_cmd "taveren-scan-cycle ../../tests/fixtures/Traffic_Light_short_orange/build/Traffic_Light_short_orange.so" \
        "Traffic_Light_short_orange_8.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/Traffic_Light_original/build/Traffic_Light_original.so" \
        "Traffic_Light_original_9.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/oven/oven.ino.elf" \
        "oven.ino.elf" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/vending_machine/arduino_build_389120/vending_machine.ino.elf" \
        "vending_machine.ino.elf" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/elevator/elevator.ino.elf" \
        "elevator.ino.elf" &

run_cmd "taveren-scan-cycle '../../tests/fixtures/water_tank/build/water_tank.so'" \
        "water_tank_1.so" &


run_cmd "taveren-scan-cycle ../../tests/fixtures/water_tank_sfc_two_sesnors/build/water_tank_sfc_two_sesnors.so" \
        "water_tank_sfc_two_sesnors_3.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/car_wash/build/car_wash.so" \
        "car_wash.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/water_tank_sfc_one_sensor/build/water_tank_sfc_one_sensor.so" \
        "water_tank_sfc_one_sensor_2.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/warehouse_lift/build/warehouse_lift.so" \
        "warehouse_lift.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/Traffic_Light_10/build/Traffic_Light.so" \
        "Traffic_Light_10.so" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/car_wash/build/carwash-mkr1010.elf" \
        "carwash-mkr1010.elf" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/traffic_light_simulink/MyBlinky.elf" \
        "MyBlinky.elf" &

run_cmd "taveren-scan-cycle ../../tests/fixtures/binaries/sf_launchabort.exe" \
        "sf_launchabort.exe" &

#run_cmd "taveren-scan-cycle ../../tests/fixtures/elevator/elevator_uno_O0.ino.elf" \
#        "elevator_uno_O0.ino.elf" &

wait
echo "All commands completed."
