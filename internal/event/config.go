// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package event

import (
	"encoding/xml"
	"errors"
	"github.com/minio/minio-go/v7/pkg/set"
)

// common - represents common elements inside <QueueConfiguration>, <CloudFunctionConfiguration>
// and <TopicConfiguration>
type common struct {
	ID     string `xml:"Id" json:"Id"`
	Filter S3Key  `xml:"Filter" json:"Filter"`
	Events []Name `xml:"Event" json:"Event"`
}

// S3Key - represents elements inside <S3Key>...</S3Key>
type S3Key struct {
	RuleList FilterRuleList `xml:"S3Key,omitempty" json:"S3Key,omitempty"`
}

// FilterRuleList - represents multiple <FilterRule>...</FilterRule>
type FilterRuleList struct {
	Rules []FilterRule `xml:"FilterRule,omitempty"`
}

// FilterRule - represents elements inside <FilterRule>...</FilterRule>
type FilterRule struct {
	Name  string `xml:"Name"`
	Value string `xml:"Value"`
}

// Queue - represents elements inside <QueueConfiguration>
type Queue struct {
	common
	ARN ARN `xml:"Queue"`
}

// ARN - SQS resource name representation.
type ARN struct {
	TargetID
	region string
}

// TargetID - holds identification and name strings of notification target.
type TargetID struct {
	ID   string
	Name string
}

// UnmarshalXML - decodes XML data.
func (q *Queue) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	// Make subtype to avoid recursive UnmarshalXML().
	type queue Queue
	parsedQueue := queue{}
	if err := d.DecodeElement(&parsedQueue, &start); err != nil {
		return err
	}

	if len(parsedQueue.Events) == 0 {
		return errors.New("missing event name(s)")
	}

	eventStringSet := set.NewStringSet()
	for _, eventName := range parsedQueue.Events {
		if eventStringSet.Contains(eventName.String()) {
			return &ErrDuplicateEventName{eventName}
		}

		eventStringSet.Add(eventName.String())
	}

	*q = Queue(parsedQueue)

	return nil
}
