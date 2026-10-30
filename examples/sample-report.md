Synthetic AWS plan demonstration. Generated from examples/risky.json.

# Terraform change review

Result: REVIEW_REQUIRED

Changed managed resources only; selected AWS attributes and lifecycle actions.

Input SHA256: f35876972b2e142af5ff1dec5dd998137bd66391254b94ad8679de59961eeae6

No resource values, policy documents or outputs are copied into this report.

## Findings

- REPLACEMENT: Resource replacement requires downtime/data review.
```text
"module.app.aws_ebs_volume.example"
```

- ENCRYPTION_DISABLED: Planned security setting is disabled: encrypted
```text
"module.app.aws_ebs_volume.example"
```

- PUBLIC_ADMIN: World TCP ingress includes SSH or RDP; review access and network reachability.
```text
"module.app.aws_vpc_security_group_ingress_rule.example"
```

## Coverage

```json
[
  {
    "address": "module.app.aws_ebs_volume.example",
    "type": "aws_ebs_volume",
    "actions": [
      "delete",
      "create"
    ],
    "attribute_check": "checked"
  },
  {
    "address": "module.app.aws_vpc_security_group_ingress_rule.example",
    "type": "aws_vpc_security_group_ingress_rule",
    "actions": [
      "create"
    ],
    "attribute_check": "checked"
  }
]
```
