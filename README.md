# Panorama Rule Reordering Utility

The main purpose behind this utility is to identify shadowed rules from a large
rulebase and help the administrator re-order them by permissiveness.
## Pre-requisites and Installation

* Python v3.6 or later
* pandevice
* pan-os-python
* PyYAML

* Download and extract this package zip file in a folder at any location.
* Open a command prompt / terminal and cd into the directory where you extracted
 this package panorama-rule-reorder.zip)

* After installing Python3 (v3.6+) you can install the pre-requisites using the pip

``` python3 -m pip install -r requirements.txt ```

## Configuration

TODO: Write GUide

```

## Usage

After configuration file is in place, run the script using python3:

``` python3 panorama-rule-reorder.py ```

To enable debugging output on console. Use the -debug flag

``` python3 panorama-rule-reorder.py -debug ```
