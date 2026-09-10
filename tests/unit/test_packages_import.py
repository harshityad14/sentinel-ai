"""Sanity tests verifying that all decoupled packages can be imported cleanly."""

import unittest


class TestPackagesImport(unittest.TestCase):
    def test_imports(self):
        import sentinel_models
        import sentinel_ingestion
        import sentinel_flow_engine
        import sentinel_features
        import sentinel_detection
        import sentinel_ai_agent

        self.assertTrue(hasattr(sentinel_models, "Alert"))
        self.assertTrue(hasattr(sentinel_models, "FlowRecord"))
        self.assertTrue(hasattr(sentinel_ingestion, "BasePacketSource"))
        self.assertTrue(hasattr(sentinel_flow_engine, "BaseFlowAggregator"))
        self.assertTrue(hasattr(sentinel_features, "BaseFeatureExtractor"))
        self.assertTrue(hasattr(sentinel_detection, "BaseDetector"))
        self.assertTrue(hasattr(sentinel_ai_agent, "BaseAnalystAgent"))


if __name__ == "__main__":
    unittest.main()
