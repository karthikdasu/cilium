// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestAddDelete(c *C) {
	//var nullPtr *Node

	tree := Tree{}

	// Empty tree should return empty result
	n, p := tree.Lookup("")
	c.Assert(n, IsNil)
	c.Assert(p, IsNil)

	root := Node{}

	// adding a root node should succeed
	added, err := tree.Add(RootNodeName, &root)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	// lookup of root node should succeed now
	n, p = tree.Lookup(RootNodeName)
	c.Assert(n, Equals, &root)
	c.Assert(n.Name, Equals, RootNodeName)
	c.Assert(p, IsNil)

	// lookup of empty path should return root node
	n, p = tree.Lookup("")
	c.Assert(n, Equals, &root)
	c.Assert(n.Name, Equals, RootNodeName)
	c.Assert(p, IsNil)

	deleted := tree.Delete(RootNodeName, "")
	c.Assert(deleted, Equals, true)

	n, p = tree.Lookup(RootNodeName)
	c.Assert(n, IsNil)
	c.Assert(p, IsNil)

	// Added a child if no root node exist must add parents of that node
	foo := &Node{Name: "foo"}
	added, err = tree.Add(RootNodeName+".bar", foo)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	// The node should exist afterwards
	n, pBar := tree.Lookup(RootNodeName + ".bar.foo")
	c.Assert(n, Equals, foo)
	c.Assert(pBar.Name, Equals, "bar")
	c.Assert(pBar.path, Equals, RootNodeName+".bar")

	// The root node should have been added
	n, p = tree.Lookup(RootNodeName)
	c.Assert(n, Not(IsNil))
	c.Assert(p, IsNil)

	fooNode := Node{}
	root = Node{
		Children: map[string]*Node{
			"foo": &fooNode,
			"bar": {},
		},
	}

	// Add root node with children, should succeed
	added, err = tree.Add(RootNodeName, &root)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	// lookup of root node should succeed now
	n, p = tree.Lookup(RootNodeName)
	// The "root" node was merged into the tree's root, therefore we need to
	// make it the same with this hack
	root.Children["bar"] = pBar
	root.resolved = true
	c.Assert(n, DeepEquals, &root)
	c.Assert(n.Name, Equals, RootNodeName)
	c.Assert(p, IsNil)

	// lookup of child foo should succeed
	n, p = tree.Lookup("root.foo")
	c.Assert(n, Equals, &fooNode)
	c.Assert(p, DeepEquals, &root)

	// delete root node
	deleted = tree.Delete("root", "")
	c.Assert(deleted, Equals, true)

	// lookup of root node should fail now
	n, p = tree.Lookup(RootNodeName)
	c.Assert(n, IsNil)
	c.Assert(p, IsNil)

	// lookup of child foo should fail now
	n, p = tree.Lookup("root.foo")
	c.Assert(n, IsNil)
	c.Assert(p, IsNil)
}
