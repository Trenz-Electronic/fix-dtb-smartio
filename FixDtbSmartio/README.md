# Introduction

FixDtbSmartio reorders device tree nodes such that the the ones with the biggest "trenz.biz,buffer-size" property values come first. This in turn determines the order of smartio probes and helps against memory fragmentation.

The file is expected to be in image.ub format (FIT image).

# Usage

FixDtbSmartio image.ub

