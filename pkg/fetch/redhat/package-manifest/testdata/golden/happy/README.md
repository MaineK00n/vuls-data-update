## Repository of Red Hat Package Manifest data accumulation

All the data in this repository are fetched from following pages by Red Hat, Inc.

- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html-single/package_manifest/index
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/package_manifest/index
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/plan-appstream
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/plan-baseos
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/plan-crb
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/plan-extensions
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/plan-high_availability
- https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/plan-supplementary

docs.redhat.com refuses automated clients, so the pages are saved from a browser by hand. origin/ keeps them, each at the path of its URL and cut down to its article element, and the tables in package/ and module/ are read from them. To store pages saved again, run in this repository:

    vuls-data-update fetch redhat-package-manifest --dir . <saved page>...

### Copyright and License notice

Copyright © Red Hat, Inc.
The text of and illustrations in this document are licensed by Red Hat under a Creative Commons Attribution–Share Alike 3.0 Unported license ("CC-BY-SA"). An explanation of CC-BY-SA is available at http://creativecommons.org/licenses/by-sa/3.0/. In accordance with CC-BY-SA, if you distribute this document or an adaptation of it, you must provide the URL for the original version.
Red Hat, as the licensor of this document, waives the right to enforce, and agrees not to assert, Section 4d of CC-BY-SA to the fullest extent permitted by applicable law.

The pages in origin/ are the documents above, cut down to their article element. Those of RHEL 8 and 9 carry their Legal Notice in it. For those of RHEL 10, see https://docs.redhat.com/en/legal-notice.
