# ===============================================================================================
# Set the parser
# ===============================================================================================

        #TODO: #60 Remove this function with enhancement
        rewrite(set_rfcnonconformant);
{{- if eq .parser "rfc5424_strict" }}
        filter(f_rfc5424_strict);
        parser {
                syslog-parser(flags(syslog-protocol  store-raw-message));
            };
        rewrite(set_rfc5424_strict);
{{- else if eq .parser "rfc5424_noversion" }}
        filter(f_rfc5424_noversion);
        parser {
                syslog-parser(flags(syslog-protocol  store-raw-message));
            };
        rewrite(set_rfc5424_noversion);
{{- else if eq .parser "cisco_parser" }}
        parser {cisco-parser()};
        rewrite(set_cisco_ios);
{{- else if eq .parser "rfc3164" }}
        parser {
            syslog-parser(time-zone({{getenv "SC4S_DEFAULT_TIMEZONE" "GMT"}}) flags(store-raw-message));
        };
        rewrite(set_rfc3164);
{{- else if eq .parser "no_parse" }}
        rewrite(set_no_parse);
{{- else }}
        if {filter(f_rfc5424_strict);
            parser {
                    syslog-parser(flags(syslog-protocol  store-raw-message));
                };
            rewrite(set_rfc5424_strict);
        } elif {
            filter(f_rfc5424_noversion);
            parser {
                    syslog-parser(flags(syslog-protocol  store-raw-message));
                };
            rewrite(set_rfc5424_noversion);
        } elif {
            parser {cisco-parser()};
            rewrite(set_cisco_ios);
        } else {
            parser {
                syslog-parser(time-zone({{getenv "SC4S_DEFAULT_TIMEZONE" "GMT"}}) flags(store-raw-message));
            };
            rewrite(set_rfc3164);
        };
{{- end }}
        rewrite(r_set_splunk_default);
        parser {
            vendor_product_by_source();
        };