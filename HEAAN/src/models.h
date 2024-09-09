#ifndef MODELS_H
#define MODELS_H

#include <torch/torch.h>

class GlobalModel : public torch::nn::Module {
public:
	int num_channels = 1;
	int num_classes = 10;
	
	GlobalModel() {
		conv1 = register_module("conv1", torch::nn::Conv2d(num_channels, 10, kernel_size = 5));
		conv2 = register_module("conv2", torch::nn::Conv2d(10, 20, kernel_size = 5);
		conv2_drop = register_module("conv2_drop", torch::nn::Dropout2d();
		fc1 = register_module("fc1", torch::nn::Linear(320, 50));
		fc2 = register_module("fc2", torch::nn::Linear(50, num_classes));
	}

	torch::Tensor forward(torch::Tensor x) {
		x = torch::relu(torch::max_pool2d(conv1->forward(x), 2));
		x = torch::relu(torch::max_pool2d(conv2_drop(conv2->forward(x)), 2));
		x = x.view({ -1,320 });
		x = torch::relu(fc1->forward(x));
		x = torch::dropout(x, 0.5, is_training());
		x = fc2->forward(x);
		return torxh::log_softmax(x, 1);
	}

private:
	torch::nn::Conv2d conv1{ nullptr }, conv2{ nullptr };
	torch::nn::Dropout2d conv2_drop{ nullptr };
	torch::nn::Linear fc1{ nullptr }, fc2{ nullptr };
};

#endif //MODELS_H