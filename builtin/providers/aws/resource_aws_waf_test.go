package aws

import (
	"testing"
)

func TestAccAWSWaf(t *testing.T) {
	testCases := map[string]map[string]func(t *testing.T){
		"ByteMatchSet": {
			"basic":              testAccWafByteMatchSet_basic,
			"changeNameForceNew": testAccWafByteMatchSet_changeNameForceNew,
			"disappears":         testAccWafByteMatchSet_disappears,
		},
		"IPSet": {
			"basic":              testAccWafIPSet_basic,
			"disappears":         testAccWafIPSet_disappears,
			"changeNameForceNew": testAccWafIPSet_changeNameForceNew,
		},
		"Rule": {
			"basic":              testAccWafRule_basic,
			"changeNameForceNew": testAccWafRule_changeNameForceNew,
			"disappears":         testAccWafRule_disappears,
		},
		"SizeConstraintSet": {
			"basic":              testAccWafSizeConstraintSet_basic,
			"changeNameForceNew": testAccWafSizeConstraintSet_changeNameForceNew,
			"disappears":         testAccWafSizeConstraintSet_disappears,
		},
		"SqlInjectionMatchSet": {
			"basic":              testAccWafSqlInjectionMatchSet_basic,
			"changeNameForceNew": testAccWafSqlInjectionMatchSet_changeNameForceNew,
			"disappears":         testAccWafSqlInjectionMatchSet_disappears,
		},
		"WebAcl": {
			"basic":               testAccWafWebAcl_basic,
			"changeNameForceNew":  testAccWafWebAcl_changeNameForceNew,
			"changeDefaultAction": testAccWafWebAcl_changeDefaultAction,
			"disappears":          testAccWafWebAcl_disappears,
		},
		"XssMatchSet": {
			"basic":              testAccWafXssMatchSet_basic,
			"changeNameForceNew": testAccWafXssMatchSet_changeNameForceNew,
			"disappears":         testAccWafXssMatchSet_disappears,
		},
	}

	for group, m := range testCases {
		m := m
		t.Run(group, func(t *testing.T) {
			t.Parallel()
			for name, tc := range m {
				tc := tc
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					tc(t)
				})
			}
		})
	}
}
