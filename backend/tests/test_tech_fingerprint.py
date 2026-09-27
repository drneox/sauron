import unittest

from modules import nuclei_integration, tech_fingerprint as tf


class VersionExtractionTests(unittest.TestCase):
    def test_server_and_powered_by_versions(self):
        v = tf.extract_versions({"server": "nginx/1.18.0 (ubuntu)", "x-powered-by": "php/7.4.3"}, "")
        self.assertEqual(v["Nginx"], "1.18.0")
        self.assertEqual(v["PHP"], "7.4.3")

    def test_server_without_version_yields_none(self):
        self.assertEqual(tf.extract_versions({"server": "nginx"}, ""), {})

    def test_generator_meta_wordpress_both_attribute_orders(self):
        a = '<meta name="generator" content="WordPress 6.4.2" />'
        b = '<meta content="WordPress 6.4.2" name="generator">'
        self.assertEqual(tf.extract_versions({}, a)["WordPress"], "6.4.2")
        self.assertEqual(tf.extract_versions({}, b)["WordPress"], "6.4.2")

    def test_joomla_generator_without_version_is_detected_but_unversioned(self):
        html = '<meta name="generator" content="Joomla! - Open Source Content Management" />'
        self.assertEqual(tf.generator_technologies(html), {"Joomla"})
        self.assertNotIn("Joomla", tf.extract_versions({}, html))

    def test_wordpress_core_version_only_from_core_assets(self):
        core = '<script src="/wp-includes/js/wp-emoji-release.min.js?ver=6.3.1"></script>'
        jq = '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1"></script>'
        self.assertEqual(tf.extract_versions({}, core)["WordPress"], "6.3.1")
        self.assertNotIn("WordPress", tf.extract_versions({}, jq))

    def test_wordpress_plugins_and_themes(self):
        html = ('<link href="/wp-content/plugins/Elementor/css/x.css?ver=3.19.0">'
                '<link href="/wp-content/themes/astra/style.css?ver=4.6.1">')
        self.assertEqual(
            tf.extract_wp_extensions(html),
            {"elementor (WP plugin)": "3.19.0", "astra (WP theme)": "4.6.1"},
        )


class HttpxTechTests(unittest.TestCase):
    def test_parses_versions_aliases_and_drops_protocol_flags(self):
        parsed = tf.parse_httpx_tech(["Nginx:1.18.0", "Microsoft ASP.NET", "HSTS", "Express", "Ubuntu"])
        self.assertEqual(parsed, {"Nginx": "1.18.0", "ASP.NET": None, "Express.js": None, "Ubuntu": None})


class NucleiTagTests(unittest.TestCase):
    def test_stack_tags_added_in_stable_order_without_duplicates(self):
        tags = nuclei_integration.tech_tags(["Nginx", "WordPress", "PHP", "Nginx", "jQuery"])
        self.assertEqual(tags, ["nginx", "wordpress", "wp-plugin", "wp-theme", "php"])

    def test_unknown_stack_adds_nothing(self):
        self.assertEqual(nuclei_integration.tech_tags(["React", "Cloudflare"]), [])


if __name__ == "__main__":
    unittest.main()
