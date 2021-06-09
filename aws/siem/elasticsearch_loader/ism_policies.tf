resource "elasticsearch_opendistro_ism_policy" "rollover_100gb" {
  policy_id = "rollover100gb"
  body      = <<EOF
{
   "policy":{
      "description":"rollover by 100gb",
      "default_state":"rollover",
      "ism_template": {
        "index_patterns": ["${join("-0*\", \"", var.rollover_indexes)}"],
        "priority": 100
      },
      "states":[
         {
            "name":"rollover",
            "actions":[
               {
                  "rollover":{
                     "min_size":"100gb"
                  }
               }
            ],
            "transitions":[]
         }
      ]
   }
}
EOF
}

resource "elasticsearch_index_template" "rollover_indexes" {
  count = length(var.rollover_indexes)
  name  = "${var.rollover_indexes[count.index]}_rollover"
  body  = <<EOF
{
  "index_patterns": ["${var.rollover_indexes[count.index]}-0*"],
  "order": ${count.index + 1},
  "settings": {
    "opendistro.index_state_management.rollover_alias": "${var.rollover_indexes[count.index]}"
  }
 }
EOF

  depends_on = [
    elasticsearch_opendistro_ism_policy.rollover_100gb
  ]
}

resource "elasticsearch_index" "initial_indexes" {
  count              = length(var.rollover_indexes)
  name               = "${var.rollover_indexes[count.index]}-000001"
  aliases            = <<EOF
{
  "${var.rollover_indexes[count.index]}":{}
}
EOF
  number_of_replicas = 1

  depends_on = [
    elasticsearch_opendistro_ism_policy.rollover_100gb,
    elasticsearch_index_template.rollover_indexes
  ]
}
