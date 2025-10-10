package salsa

type PackageAnnotation packageAnnotation

func MaxPackageStatus(cves []PackageAnnotation, advs map[string][]PackageAnnotation) PackageAnnotation {
	cs := make([]packageAnnotation, 0, len(cves))
	for _, c := range cves {
		cs = append(cs, packageAnnotation(c))
	}
	as := make(map[string][]packageAnnotation)
	for k, v := range advs {
		pss := make([]packageAnnotation, 0, len(v))
		for _, p := range v {
			pss = append(pss, packageAnnotation(p))
		}
		as[k] = pss
	}

	return PackageAnnotation(maxPackageAnnotation(cs, as))
}

func MaxSeverity(anns []PackageAnnotation) (*string, error) {
	as := make([]packageAnnotation, 0, len(anns))
	for _, a := range anns {
		as = append(as, packageAnnotation(a))
	}
	return maxSeverity(as)
}
