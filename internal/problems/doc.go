// Package problems collects every problem one validation finds, each wrapping
// the configuration sentinel of the package that validates, and joins them into
// a single error, so that a constructor reports all that is wrong with its
// input at once; [List.ScopeToken] is the one rule of a scope token and
// [List.Scopes] the one of a scope list.
package problems
