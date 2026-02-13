package checks

import (
	"bptools/awsdata"
	"bptools/checker"
	"strings"
)

// RegisterCassandraChecks registers Cassandra (Keyspaces) checks.
func RegisterCassandraChecks(d *awsdata.Data) {
	checker.Register(TaggedCheck(
		"cassandra-keyspace-tagged",
		"Checks if Amazon Keyspaces (for Apache Cassandra) keyspaces have tags. Optionally, you can specify tag keys. The rule is NON_COMPLIANT if there are no tags or if the specified tag keys are not present. The rule does not check for tags starting with 'aws:'.",
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
				if cassandraIsSystemKeyspace(id) {
					continue
				}
				// tags map keyed by ARN; if unknown, it will be empty.
				res = append(res, TaggedResource{ID: id, Tags: tags[id]})
			}
			return res, nil
		},
	))
}

func cassandraIsSystemKeyspace(name string) bool {
	v := strings.ToLower(strings.TrimSpace(name))
	return strings.HasPrefix(v, "system")
}
