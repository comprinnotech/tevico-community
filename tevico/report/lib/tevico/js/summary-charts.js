// Constants and Types
const ChartType = {
  BAR: 'bar',
  DONUT: 'donut',
  PIE: 'pie'
};

const ChartCategory = {
  SEVERITY: 'severity',
  SERVICE: 'service',
  SECTION: 'section'
};

const Status = {
  FAILED: 'failed',
  PASSED: 'passed'
};

const severityOrder = ['critical', 'high', 'medium', 'low'];

// Configuration
class ChartConfig {
  static heights = {
    'failed-by-severity': 240,
    'failed-by-service': 252,
    'failed-by-section': 255,
    'passed-by-severity': 240,
    'passed-by-service': 252,
    'passed-by-section': 255
  };

  static baseBarConfig = {
    toolbar: { show: false },
    tooltip: {
      y: {
        formatter: (val) => `${val}%`,
        title: { formatter: () => "Percentage: " }
      }
    },
    plotOptions: {
      bar: {
        borderRadius: 4,
        horizontal: true,
        dataLabels: { position: 'top' }
      }
    },
    dataLabels: {
      enabled: true,
      offsetX: 40,
      style: {
        fontSize: '12px',
        fontWeight: 'bold',
        colors: ['#333']
      },
      formatter: (val) => {
        const value = parseFloat(val);
        return value.toFixed(2) + ' %';
      }
    },
    xaxis: {
      axisBorder: { show: false },
      axisTicks: { show: false },
      labels: { show: false }
    },
    yaxis: {
      axisBorder: { show: false },
      axisTicks: { show: false }
    },
    grid: { show: false }
  };

  static baseCircularConfig = {
    tooltip: {
      enabled: true,
      y: {
        formatter: (value) => value + ' checks',
        title: {
          formatter: (seriesName) => seriesName + ':'
        }
      }
    },
    responsive: [{
      options: {
        legend: { position: 'bottom' }
      }
    }]
  };
}

// Data Processing
class DataProcessor {
  static processMetricsByCategory(data, status, category) {
    const items = data[`by_${category}s`];
    return items
      .sort((a, b) => b.check_status[status] - a.check_status[status])
      .reduce((acc, item) => {
        acc.series.push(item.check_status[status]);
        acc.labels.push(item.name);
        return acc;
      }, { series: [], labels: [] });
  }

  static calculatePercentages(data, status) {

    const severityMap = new Map();

    severityOrder.forEach(severity => {
      severityMap.set(severity, {
        value: '0.00',
        name: toTitleCase(severity)
      });
    });

    const totalByStatus = data.by_severities.reduce((acc, item) => {
      acc += item.check_status[status];
      return acc;
    }, 0);

    data.by_severities.forEach(item => {
      if (severityMap.has(item.name)) {
        severityMap.set(item.name, {
          value: ((item.check_status[status] / totalByStatus) * 100).toFixed(2),
          name: toTitleCase(item.name)
        });
      }
    });

    return severityOrder.map(severity => severityMap.get(severity));
  }

}

toTitleCase = (string) => string.charAt(0).toUpperCase() + string.slice(1).toLowerCase();

class ChartBuilder {
  static createBarChart(elementId, data) {
    const status = elementId.startsWith(Status.PASSED) ? Status.PASSED : Status.FAILED;
    const metrics = DataProcessor.calculatePercentages(data, status);

    return {
      series: [{ data: metrics.map(m => m.value) }],
      chart: {
        type: ChartType.BAR,
        height: ChartConfig.heights[elementId],
        toolbar: ChartConfig.baseBarConfig.toolbar,
      },
      ...ChartConfig.baseBarConfig,
      xaxis: {
        ...ChartConfig.baseBarConfig.xaxis,
        categories: metrics.map(m => m.name)
      }
    };
  }

  static createCircularChart(elementId, data, chartType) {
    const status = elementId.startsWith(Status.PASSED) ? Status.PASSED : Status.FAILED;
    const category = elementId.includes('service') ? ChartCategory.SERVICE : ChartCategory.SECTION;
    const { series, labels } = DataProcessor.processMetricsByCategory(data, status, category);

    return {
      series,
      labels,
      chart: {
        type: chartType,
        height: ChartConfig.heights[elementId]
      },
      ...ChartConfig.baseCircularConfig
    };
  }
}

// Chart Manager
class ChartManager {
  #charts = new Map();

  async initialize() {
    try {
      const data = check_analytics;
      await this.#renderCharts(data);
    } catch (error) {
      console.error('Chart initialization failed:', error);
      throw error;
    }
  }

  async #renderCharts(data) {
    const renderTasks = [
      this.#renderSeverityCharts(data),
      this.#renderServiceCharts(data),
      this.#renderSectionCharts(data)
    ];

    await Promise.all(renderTasks);
  }

  async #renderSeverityCharts(data) {
    await Promise.all([
      this.#renderChart('failed-by-severity', data, ChartBuilder.createBarChart),
      this.#renderChart('passed-by-severity', data, ChartBuilder.createBarChart)
    ]);
  }

  async #renderServiceCharts(data) {
    await Promise.all([
      this.#renderChart('failed-by-service', data,
        (id, data) => ChartBuilder.createCircularChart(id, data, ChartType.DONUT)),
      this.#renderChart('passed-by-service', data,
        (id, data) => ChartBuilder.createCircularChart(id, data, ChartType.DONUT))
    ]);
  }

  async #renderSectionCharts(data) {
    await Promise.all([
      this.#renderChart('failed-by-section', data,
        (id, data) => ChartBuilder.createCircularChart(id, data, ChartType.PIE)),
      this.#renderChart('passed-by-section', data,
        (id, data) => ChartBuilder.createCircularChart(id, data, ChartType.PIE))
    ]);
  }

  async #renderChart(elementId, data, configBuilder) {
    try {
      const element = document.getElementById(elementId);
      if (!element) {
        throw new Error(`Element ${elementId} not found`);
      }

      const config = configBuilder(elementId, data);
      const chart = new ApexCharts(element, config);
      await chart.render();
      this.#charts.set(elementId, chart);
    } catch (error) {
      console.error(`Failed to render chart ${elementId}:`, error);
    }
  }

  cleanup() {
    this.#charts.forEach(chart => chart.destroy());
    this.#charts.clear();
  }
}

// Initialize charts
document.addEventListener('DOMContentLoaded', () => {
  const chartManager = new ChartManager();
  chartManager.initialize().catch(error => {
    console.error('Failed to initialize charts:', error);
  });

  // Cleanup on page unload
  window.addEventListener('unload', () => chartManager.cleanup());
});