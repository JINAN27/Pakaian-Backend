const ShippingCost = require('../models/ShippingCost');
const Order = require('../models/Order');

exports.getProvinces = async (req, res) => {
  // This is a mock function. In a real application, you would fetch this data from an API or database
  const provinces = [
    { id: '1', name: 'Jawa Barat' },
    { id: '2', name: 'Jawa Tengah' },
    { id: '3', name: 'Jawa Timur' },
  ];
  res.json(provinces);
};

exports.getCities = async (req, res) => {
  // This is a mock function. In a real application, you would fetch this data from an API or database
  const cities = [
    { id: '1', name: 'Bandung' },
    { id: '2', name: 'Cirebon' },
    { id: '3', name: 'Bekasi' },
  ];
  res.json(cities);
};

exports.getDistricts = async (req, res) => {
  // This is a mock function. In a real application, you would fetch this data from an API or database
  const districts = [
    { id: '1', name: 'Cicendo' },
    { id: '2', name: 'Andir' },
    { id: '3', name: 'Astana Anyar' },
  ];
  res.json(districts);
};

exports.calculateShippingCost = async (req, res) => {
  const { province, city, district } = req.body;
  const { orderId } = req.params;

  try {
    // In a real application, you would calculate the shipping cost based on the order details and shipping address
    const shippingCost = {
      cost: Math.floor(Math.random() * 50000) + 10000, // Random cost between 10,000 and 60,000
      province,
      city,
      district
    };

    res.json({ shippingCost });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};

exports.confirmShipping = async (req, res) => {
  const { orderId } = req.params;
  const { shippingCost,
    shippingAddress: { province, city, district }
  } = req.body;

  try {
    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    order.shippingDetails = {
      cost: shippingCost,
      province,
      city,
      district
    };

    await order.save();

    res.json({ message: 'Shipping confirmed', order });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err.message });
  }
};