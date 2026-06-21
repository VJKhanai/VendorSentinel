(function () {
    "use strict";

    function onReady(callback) {
        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", callback, { once: true });
        } else {
            callback();
        }
    }

    function readFigure(elementId) {
        const element = document.getElementById(elementId);

        if (!element) {
            throw new Error("Missing chart data element: " + elementId);
        }

        const raw = element.textContent.trim();

        if (!raw) {
            throw new Error("Empty chart data: " + elementId);
        }

        return JSON.parse(raw);
    }

    function showChartError(containerId, message) {
        const container = document.getElementById(containerId);

        if (!container) {
            return;
        }

        container.innerHTML =
            "<div style='" +
            "display:grid;" +
            "place-items:center;" +
            "min-height:330px;" +
            "padding:24px;" +
            "border-radius:12px;" +
            "color:#b4232f;" +
            "background:#fff7f8;" +
            "text-align:center;" +
            "font-size:12px;" +
            "'>" +
            message +
            "</div>";
    }

    function renderDashboardCharts() {
        const chartIds = [
            "riskChart",
            "categoryRiskChart",
            "topRiskChart"
        ];

        if (!window.Plotly || typeof window.Plotly.newPlot !== "function") {
            const message =
                "Plotly did not load. Confirm static/js/plotly.min.js was copied.";

            chartIds.forEach(function (id) {
                showChartError(id, message);
            });

            console.error(message);
            return;
        }

        let riskFigure;
        let categoryFigure;
        let topRiskFigure;

        try {
            riskFigure = readFigure("risk-chart-data");
            categoryFigure = readFigure("category-chart-data");
            topRiskFigure = readFigure("top-risk-chart-data");
        } catch (error) {
            console.error("Chart JSON error:", error);

            chartIds.forEach(function (id) {
                showChartError(
                    id,
                    "Chart data could not be read. Check the Flask dashboard route."
                );
            });

            return;
        }

        const config = {
            responsive: true,
            displayModeBar: false,
            displaylogo: false,
            scrollZoom: false
        };

        const commonFont = {
            family: "Inter, system-ui, sans-serif",
            color: "#53627a"
        };

        riskFigure.layout = Object.assign(
            {},
            riskFigure.layout || {},
            {
                height: 430,
                font: commonFont,
                paper_bgcolor: "rgba(0,0,0,0)",
                plot_bgcolor: "rgba(0,0,0,0)",
                margin: { l: 30, r: 30, t: 15, b: 62 },
                legend: {
                    orientation: "h",
                    x: 0.5,
                    xanchor: "center",
                    y: -0.08,
                    font: { size: 10, color: "#53627a" }
                }
            }
        );

        if (riskFigure.data && riskFigure.data[0]) {
            riskFigure.data[0].hole = 0.62;
            riskFigure.data[0].sort = false;
            riskFigure.data[0].textinfo = "label+percent";
            riskFigure.data[0].textposition = "outside";
            riskFigure.data[0].marker = {
                colors: ["#2aa876", "#d6a12a", "#d9424e", "#f07b3f"],
                line: { color: "#ffffff", width: 5 }
            };
            riskFigure.data[0].hovertemplate =
                "<b>%{label}</b><br>" +
                "Vendors: %{value}<br>" +
                "Portfolio share: %{percent}" +
                "<extra></extra>";
        }

        categoryFigure.layout = Object.assign(
            {},
            categoryFigure.layout || {},
            {
                height: 410,
                font: commonFont,
                paper_bgcolor: "rgba(0,0,0,0)",
                plot_bgcolor: "rgba(0,0,0,0)",
                margin: { l: 52, r: 24, t: 15, b: 105 },
                showlegend: false
            }
        );

        categoryFigure.layout.xaxis = Object.assign(
            {},
            categoryFigure.layout.xaxis || {},
            {
                tickfont: { size: 10, color: "#65738a" },
                linecolor: "#dfe5ee",
                gridcolor: "rgba(0,0,0,0)",
                automargin: true
            }
        );

        categoryFigure.layout.yaxis = Object.assign(
            {},
            categoryFigure.layout.yaxis || {},
            {
                tickfont: { size: 10, color: "#65738a" },
                gridcolor: "#edf1f6",
                zeroline: false,
                range: [0, 100]
            }
        );

        if (categoryFigure.data && categoryFigure.data[0]) {
            categoryFigure.data[0].marker = {
                color: [
                    "#315efb", "#4975ff", "#5d8bff", "#72a0ff", "#8ab4ff",
                    "#65b9b1", "#4eaaa2", "#379b93", "#238c84", "#147b74"
                ],
                line: { color: "#ffffff", width: 1 }
            };
            categoryFigure.data[0].textfont = {
                family: "Inter, system-ui, sans-serif",
                color: "#22314d",
                size: 10
            };
        }

        topRiskFigure.layout = Object.assign(
            {},
            topRiskFigure.layout || {},
            {
                height: 410,
                font: commonFont,
                paper_bgcolor: "rgba(0,0,0,0)",
                plot_bgcolor: "rgba(0,0,0,0)",
                margin: { l: 175, r: 52, t: 15, b: 55 },
                showlegend: false
            }
        );

        topRiskFigure.layout.xaxis = Object.assign(
            {},
            topRiskFigure.layout.xaxis || {},
            {
                range: [0, 105],
                gridcolor: "#edf1f6",
                zeroline: false,
                tickfont: { size: 10, color: "#65738a" }
            }
        );

        topRiskFigure.layout.yaxis = Object.assign(
            {},
            topRiskFigure.layout.yaxis || {},
            {
                automargin: true,
                tickfont: { size: 10, color: "#34435d" }
            }
        );

        const jobs = [
            ["riskChart", riskFigure],
            ["categoryRiskChart", categoryFigure],
            ["topRiskChart", topRiskFigure]
        ];

        jobs.forEach(function (job) {
            const containerId = job[0];
            const figure = job[1];

            window.Plotly.newPlot(
                containerId,
                figure.data || [],
                figure.layout || {},
                config
            ).catch(function (error) {
                console.error("Failed to render " + containerId + ":", error);
                showChartError(
                    containerId,
                    "This graph could not be rendered. Check the browser console."
                );
            });
        });

        window.addEventListener("resize", function () {
            chartIds.forEach(function (id) {
                const element = document.getElementById(id);

                if (element && element.data) {
                    window.Plotly.Plots.resize(element);
                }
            });
        });
    }

    onReady(renderDashboardCharts);
})();
