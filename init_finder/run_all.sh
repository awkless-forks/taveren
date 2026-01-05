#!/bin/bash

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

run_cmd "python init_finder.py ../artifacts/packaging_sfc/build/packaging_sfc.so 0x4236C0" \
        "packaging_sfc.so" &

run_cmd "python init_finder.py ../artifacts/packaging_sfc/build/packaging_sfc_mips.so 0x416634" \
        "packaging_sfc_mips.so" &
#
run_cmd "python init_finder.py ../artifacts/packaging_sfc/build/packaging_sfc_powerpc.so 0x41689c" \
        "packaging_sfc_powerpc.so" &

run_cmd "python init_finder.py ../artifacts/traffic_light_addsensor_x86-64/Traffic_Light_addsensor_x86-64.so 0x42C83D " \
        "Traffic_Light_addsensor_x86-64_4.so" &

run_cmd "python init_finder.py ../artifacts/Traffic_Light_Short_Ped_5/build/Traffic_Light_Short_Ped.so 0x42BF53" \
        "Traffic_Light_Short_Ped_5.so" &

run_cmd "python init_finder.py ../artifacts/Traffic_Light_Short_Ped_6/build/Traffic_Light_Short_Ped.so 0x42C698" \
        "Traffic_Light_Short_Ped_6.so" &

run_cmd "python init_finder.py ../artifacts/Traffic_Light_both_green_7/build/Traffic_Light_both_green.so 0x42BF53" \
        "Traffic_Light_both_green_7.so" &


run_cmd "python init_finder.py  ../artifacts/Traffic_Light_short_orange/build/Traffic_Light_short_orange.so 0x42BF53" \
        "Traffic_Light_short_orange_8.so" &

run_cmd "python init_finder.py ../artifacts/Traffic_Light_original/build/Traffic_Light_original.so 0x42C034" \
        "Traffic_Light_original_9.so" &

run_cmd "python init_finder.py ../artifacts/oven/oven.ino.elf loop" \
        "oven.ino.elf" &

run_cmd "python init_finder.py ../artifacts/vending_machine/arduino_build_389120/vending_machine.ino.elf _Z14vendingMachinev" \
        "vending_machine.ino.elf" &

run_cmd "python init_finder.py ../artifacts/elevator/elevator.ino.elf loop" \
        "elevator.ino.elf" &

run_cmd "python init_finder.py ../artifacts/water_tank/build/water_tank.so 0x41C24A" \
        "water_tank_1.so" &


run_cmd "python init_finder.py ../artifacts/water_tank_sfc_two_sesnors/build/water_tank_sfc_two_sesnors.so 0x436870" \
        "water_tank_sfc_two_sesnors_3.so" &

run_cmd "python init_finder.py ../artifacts/car_wash/build/car_wash.so 0x438395 " \
        "car_wash.so" &

run_cmd "python init_finder.py ../artifacts/water_tank_sfc_one_sensor/build/water_tank_sfc_one_sensor.so 0x4235C9" \
        "water_tank_sfc_one_sensor_2.so" &

run_cmd "python init_finder.py ../artifacts/warehouse_lift/build/warehouse_lift.so 0x423A54" \
        "warehouse_lift.so" &

run_cmd "python init_finder.py ../artifacts/Traffic_Light_10/build/Traffic_Light.so 0x42C698" \
        "Traffic_Light_10.so" &

run_cmd "python init_finder.py ../artifacts/car_wash/build/carwash-mkr1010.elf 0x2da5" \
        "carwash-mkr1010.elf" &

run_cmd "python init_finder.py ../artifacts/traffic_light_simulink/MyBlinky.elf MyBlinky_step" \
        "MyBlinky.elf" &

run_cmd "python init_finder.py ../artifacts/binaries/sf_launchabort.exe 0x4015CD" \
        "sf_launchabort.exe" &

#run_cmd "python init_finder.py ../artifacts/elevator/elevator_uno_O0.ino.elf loop" \
#        "elevator_uno_O0.ino.elf" &

wait
echo "All commands completed."
