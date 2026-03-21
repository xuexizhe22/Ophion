#!/bin/bash
sed -i 's/tsc = vcpu->tsc_cpuid_entry/tsc = vcpu->tsc_cpuid_entry - 200/g' src/vmexit.c
