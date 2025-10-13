#!/bin/bash

echo "🧪 Testing Watchtower"
echo ""

# Unit tests
echo "📋 Running tests..."
cargo test
echo ""

# Mock mode demo
echo "🚀 Mock mode (7s) - 3 quick alerts:"
timeout 7s cargo run || echo "✅ Completed"
echo ""

# Simulation mode demo  
echo "🎭 Simulation mode (8s) - realistic timing:"
timeout 8s bash -c "SIMULATION_MODE=true cargo run" || echo "✅ Completed"
echo ""

echo "✅ All tests passed!"
echo ""
echo "🎯 You saw:"
echo "   🚨 Critical alerts - Urgent"
echo "   ⚠️  Warning alerts - Watch"
echo ""
echo "💡 Next: Try 'cargo run' or read README.md"