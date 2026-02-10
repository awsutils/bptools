package checks

import (
	"bptools/awsdata"
	"bptools/checker"
)

// RegisterCassandraChecks registers Cassandra (Keyspaces) checks.
func RegisterCassandraChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"cassandra-keyspace-tagged",
		"This rule checks tagging for cassandra keyspace exist.",
		"cassandra",
		d,
		func(d *awsdata.Data) ([]TaggedResource, error) {
			keyspaces, err := d.CassandraKeyspaces.Get()
			if err != nil {
				return nil, err
			}
			tags, err := d.CassandraKeyspaceTags.Get()
			if err != nil {
				return nil, err
			}
			var res []TaggedResource
			for _, ks := range keyspaces {
				id := "unknown"
				if ks.KeyspaceName != nil {
					id = *ks.KeyspaceName
				}
				// tags map keyed by ARN; if unknown, it will be empty.
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))
}
