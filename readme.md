# Datacon 2021 物联网设备自动化漏洞挖掘

## Tools

IDA Pro 7.3/7.5/7.6 + idapython(py3)

## Methods

- Call-chain scanner
- Context-based args tracer, which limited in one code block

## TODO

- The scanner traces args in preds blocks in 2 stage now
  - Scan in 2 stage firstly
  - Then scan in 3 stage
  - if no const found, scan the whole cfg
- When a const arg has been found, it may belong to another function call
  - When a const arg has been caught, check AST

## Contributor

MozhuCY, C0ss4ck