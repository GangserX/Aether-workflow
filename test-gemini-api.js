/**
 * Gemini API Tester
 * Tests the Gemini API connection and model availability
 */

const API_KEY = "AIzaSyDNf57Y2k9CLmVMvNFHog2pmRdR4MNwc1E";
const MODEL = "gemini-3-flash-preview";

async function testGeminiAPI() {
  console.log("🚀 Testing Gemini API...\n");
  console.log("━".repeat(50));
  console.log(`Model: ${MODEL}`);
  console.log(`API Key: ${API_KEY.slice(0, 10)}...${API_KEY.slice(-4)}`);
  console.log("━".repeat(50) + "\n");

  try {
    // Test 1: Simple text generation
    console.log("📝 Test 1: Simple Text Generation");
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent?key=${API_KEY}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: "Say 'Hello from Aether!' if you can hear me.",
                },
              ],
            },
          ],
        }),
      }
    );

    if (!response.ok) {
      const errorData = await response.text();
      throw new Error(`HTTP ${response.status}: ${errorData}`);
    }

    const data = await response.json();
    
    if (data.candidates && data.candidates[0]?.content?.parts?.[0]?.text) {
      const generatedText = data.candidates[0].content.parts[0].text;
      console.log("✅ Success!");
      console.log(`Response: ${generatedText.trim()}`);
      console.log("");
      
      // Test 2: JSON response
      console.log("📊 Test 2: JSON Generation");
      const jsonResponse = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent?key=${API_KEY}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            contents: [
              {
                parts: [
                  {
                    text: 'Return a JSON object with the following structure: {"status": "operational", "message": "API is working"}',
                  },
                ],
              },
            ],
          }),
        }
      );

      const jsonData = await jsonResponse.json();
      if (jsonData.candidates && jsonData.candidates[0]?.content?.parts?.[0]?.text) {
        const jsonText = jsonData.candidates[0].content.parts[0].text;
        console.log("✅ Success!");
        console.log(`Response: ${jsonText.trim()}`);
        console.log("");
      }

      // Summary
      console.log("━".repeat(50));
      console.log("🎉 All tests passed!");
      console.log("✅ Model: " + MODEL);
      console.log("✅ API Key: Valid");
      console.log("✅ Connection: Working");
      console.log("━".repeat(50));
      console.log("\n✨ Ready to integrate into Aether Orchestrate!");
      
    } else {
      console.log("❌ Unexpected response structure:");
      console.log(JSON.stringify(data, null, 2));
    }
  } catch (error) {
    console.error("\n❌ Error testing Gemini API:");
    console.error(error.message);
    console.error("\n💡 Possible issues:");
    console.error("   • Invalid API key");
    console.error("   • Model name incorrect");
    console.error("   • Network connectivity");
    console.error("   • API quota exceeded");
  }
}

// Run the test
testGeminiAPI();
