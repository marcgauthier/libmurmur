// Package crlrevoke proves certificate revocation is enforced on
// the live mesh: nodes with a CRL revoking a peer refuse its
// sessions in both directions while the rest of the mesh converges.
package crlrevoke
