from algorithms.financial_risk import calculate_financial_risk


test_vendors = [
    {
        "vendor_name": "Strong Vendor",
        "financial_rating": "A",
        "financial_score": 2,
    },
    {
        "vendor_name": "Moderate Vendor",
        "financial_rating": "B-",
        "financial_score": 7,
    },
    {
        "vendor_name": "Distressed Vendor",
        "financial_rating": "D",
        "financial_score": 10,
    },
]


for vendor in test_vendors:
    result = calculate_financial_risk(vendor)

    print("\nVendor:", vendor["vendor_name"])
    print("Rating:", result["rating"])
    print("Financial Risk Score:", result["score"])
    print("Reasons:", result["reasons"])
    print("Recommendations:", result["recommendations"])