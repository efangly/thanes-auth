package domain

// TenantKind is what sort of organisation a tenant is.
type TenantKind string

const (
	TenantKindHospital TenantKind = "HOSPITAL"
	TenantKindLab      TenantKind = "LAB"
	TenantKindFactory  TenantKind = "FACTORY"
	TenantKindClinic   TenantKind = "CLINIC"
	TenantKindPharmacy TenantKind = "PHARMACY"
	TenantKindOther    TenantKind = "OTHER"
)

func (k TenantKind) IsValid() bool {
	switch k {
	case TenantKindHospital, TenantKindLab, TenantKindFactory, TenantKindClinic, TenantKindPharmacy, TenantKindOther:
		return true
	}
	return false
}
