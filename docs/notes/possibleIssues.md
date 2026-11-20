# General
- I think tag scaling is being applies before it gets passed to the Protocol ingestion engine
  - Not sure if tag scaling will be applied correctly
    - Considering the cases of multi register tags, or tags with endian / byte swap settings

# Modbus
- How are commands being captured in the database?
  - Particularly for multi register writes?
    - Is it analysing the bytes, translating to tag definitions, and logging it - just like read commands?
    - Or is it only storing it in the commands table for replay, and won't be available for trending in the same way as read commands?
- Is there an option to stop storing unmapped registers?
  - Should be a CLI argument to turn on/off storing unmapped registers in the DB
