import angr


class uart_atoi(angr.SimProcedure):
    def run(self, this, buffer):
        if self.arch.name in ["ARMCortexM"]:
            uart_addr = 0x2000050C
            uart_val = self.state.memory.load(uart_addr, 4, endness=self.arch.memory_endness)
            self.state.regs._r0 = uart_val
            return None
        else:
            raise NotImplementedError(f"Not implemented for {self.arch.name}")


class pinMode(angr.SimProcedure):
    def run(self, pin, mode):
        if self.arch.name in ["ARMCortexM"]:
            # import ipdb; ipdb.set_trace()
            pin = self.state.regs._r0
            if pin.op == "BVV":
                pin = pin.concrete_value
            mode = self.state.regs._r1
            print(f"pinMode {pin} set to {mode}")
            self.state.globals[pin] = mode
            return None
        if self.arch.name == "AVR":
            # TODO: Not sure if this is correct
            pin = self.state.regs.R25_R24
            mode = self.state.regs.R22
            if pin.concrete:
                pin = pin.concrete_value
            if mode.concrete:
                mode = mode.concrete_value
            mode_str = "INPUT" if mode == 0 else "OUTPUT" if mode == 1 else f"UNKNOWN({mode})"
            print(f"pinMode {pin} set to {mode_str}")
            self.state.globals[pin] = mode
            return None
        else:
            raise NotImplementedError(f"Not implemented for {self.arch.name}")

class print_all(angr.SimProcedure):
    def run(self, x):
        if self.arch.name in ["ARMCortexM"]:
            print("print")
            return None
        elif self.arch.name == "AVR":
            print("print")
            return None
        else:
            raise NotImplementedError(f"Not implemented for {self.arch.name}")


class get_time_ms(angr.SimProcedure):
    def run(self):
        if self.arch.name in ["ARMCortexM"]:
            time_addr = 0xa0000000
            prev = self.state.memory.load(time_addr, self.arch.bytes, endness=self.arch.memory_endness)

            self.state.regs._r0 = prev
            # increase time every time it is called after return
            self.state.memory.store(time_addr, prev + 1, endness=self.arch.memory_endness)
            return None

class delay(angr.SimProcedure):
    def run(self, ms):
        time_addr = 0xa0000000
        prev = self.state.memory.load(time_addr, self.arch.bytes, endness=self.arch.memory_endness)
        self.state.memory.store(time_addr, prev + ms, endness=self.arch.memory_endness)
        # print(self.state.solver.eval(self.state.memory.load(0x200002fc, 4, endness=self.arch.memory_endness)))
        return None


class digitalWrite(angr.SimProcedure):
    def run(self, pin, val):
        if self.arch.name in ["ARMCortexM"]:
            pin = self.state.regs._r0
            val = self.state.regs._r1
            print("digitalWrite")
            print(pin, val)
            # get the int
            if pin.op == "BVV":
                pin = pin.concrete_value
            self.state.globals[pin] = val
            return None
        else:
            raise NotImplementedError(f"Not implemented for {self.arch.name}")


class digitalRead(angr.SimProcedure):
    def run(self, pin):
        if self.arch.name in ["ARMCortexM"]:
            pin = self.state.regs._r0
            print("digitalRead")
            print(pin)
            # get the int
            if pin.op == "BVV":
                pin = pin.concrete_value
            return self.state.globals[pin]
        elif self.arch.name == "AVR":
            pin = self.state.regs.R25_R24
            print("digitalRead")
            print(pin)
            # get the int
            if pin.op == "BVV":
                pin = pin.concrete_value
            self.state.regs.R25_R24 = self.state.globals[pin]
            return None
        else:
            raise NotImplementedError(f"Not implemented for {self.arch.name}")