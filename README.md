# IrisMISPModule

An interface module for MISP and Iris to automatically enrich IOCs with MISP insight.  
**Module type** : ``Processor``  
**Min IRIS version required** : ``> 1.4.0`` 

The module is preinstalled and registered by default on IRIS. For a manual installation please see the Installation section of this readme.

## Configuration 
Please refer to the [IRIS documentation](https://docs.dfir-iris.org/operations/modules/natives/IrisMISP/). 

## Native IOC enrichment (IRIS 3)

Since module version ``1.5.0``, IrisMISP populates the IRIS 3 native IOC
enrichment panel in addition to the ``MISP Report`` attribute. The panel is fed
from ``ioc.ioc_enrichment`` and is rendered in the IOC details view. The module
writes a ``misp`` source with a concise summary of the results: match status,
number of matching events, highest MISP threat level, tags, classifications,
event identifiers and links to the matching MISP events.

The behaviour is controlled by the ``Populate native IOC enrichment`` setting
(``misp_populate_enrichment``), enabled by default. Disable it to keep the
pre-IRIS-3 behaviour where only the ``MISP Report`` attribute is written.

Notes:

- Enrichment data written by other modules is preserved: only the ``misp``
  source key is replaced.
- A MISP match is not by itself a malicious verdict. The enrichment payload
  therefore does not set a ``verdict``; the MISP threat level and tags are
  reported instead, and the verdict is left to modules that can classify the
  IOC.
- The legacy ``MISP Report`` HTML attribute remains available, for both manual
  and automatic triggers, and contains the full raw MISP results.
- For ``domain|ip`` IOCs the domain and IP results are merged into a single
  enrichment source instead of the last search replacing the previous one.
- The raw ``events`` view of the enrichment is capped to 25 events to keep the
  IOC payload bounded; the complete raw results stay in the ``MISP Report``
  attribute.
- IRIS keeps the module configuration stored when the module was registered.
  A configuration stored before this option existed does not contain it: the
  module then falls back to the enabled default, so the enrichment works
  without reconfiguration. Re-register the module to expose the setting in the
  administration interface.

## Installation 
 The installation can however be done manually if required, 
either from sources or existing packages (go to step 3.)

1. Git clone this repository ``git clone https://github.com/dfir-iris/iris-misp-module.git && cd iris-misp-module``
2. Build the wheel : ``python3 setup.py bdist_wheel`` 
3. Copy the wheel into the IRIS app docker container ``docker cp iris_misp_module-XX-py3-none-any.whl container:/iriswebapp/dependencies/``
4. Get an interactive shell on the docker : ``docker exec -it container /bin/sh``
5. Install the new package ``pip3 install dependencies/iris_misp_module-XX-py3-none-any.whl``

## Tests

The module tests are offline unit tests: they stub the IRIS backend imports and
mock the pymisp client, so no MISP instance or IRIS deployment is required.

```
pip install -r requirements.txt pytest jinja2
python -m pytest iris_misp_module/tests
```

