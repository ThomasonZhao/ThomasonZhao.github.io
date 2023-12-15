---
title: >-
  Paper Review: Concerning an Heuristic Point of View Toward the Emission and
  Transformation of Light
date: 2021-04-11 12:03:54
category: Academic Paper
tags:
    - Quantum Physics
---

## 论文概述

爱因斯坦指出，麦克斯韦的经典电磁辐射理论与气体和其他物质的理论模型有极大的不同。当考虑位置和速度来确定有限多原子核电子构成的物体的状态时，我们会使用连续的空间函数确定其空间所属的状态，因此使用数量有限的物理量是无法充分决定其空间的电磁状态。而根据麦克斯韦理论，能量的表述是连续的。但是根据物理学家先前的观点，可测量物体的能量应该由它的原子和电子的总和来表征。可测量物体的能量是不能被分解到任意多、任意小的部分的。因此，连续空间函数描述光的理论会存在一些矛盾，尽管我们已经证实了部分相关的实验（言外之意，除这些实验之外我们没有办法判断连续函数描述的光是正确的）。

因此，如果我们假设光的能量在空间中分布为量子化的，每份量子都作为一个整体能够被吸收或者释放，那么对于黑体辐射，光激发光，由紫外线产生阴极射线（光电效应）等光的产生与转化将更容易被接受和理解。

>   “The wave theory of light, which operates with continuous spatial functions, has worked well in the representation of purely optical phenomena and will probably never be replaced by another theory. It should be kept in mind, however, that the optical observations refer to time averages rather than instantaneous values. In spite of the complete experimental confirmation of the theory as applied to diffraction, reflection, refraction, dispersion, etc., it is still conceivable that the theory of light which operates with continuous spatial functions may lead to contradictions with experience when it is applied to the phenomena of emission and transformation of light.”
>
>   译文：由连续空间函数描述的光的波动理论，已经被极好地证明了它在描述纯粹光学现象的优越性，并且或将永远不会被另一个理论所替代。但是，我们必须记住，光学观察依赖于时间平均值而非瞬时值；并且，我们有理由相信，除了衍射、反射、折射、散射等理论已被实验完整确认外，当由连续空间函数描述的光的理论被运用于描述光的产生和转化的现象时，它将会导致矛盾。

## 黑体辐射的一个理论困难

我们通过想象一个充满自由移动的电子和气体分子、具有完美反射壁的空腔来说明这种差异。此外，空腔中充满了数个电子，这些电子被力束缚在空间分离的点上，这些力随分离度线性变化，他称之为“谐振器”，因为它们吸收和发射特定频率的电磁波。他指出，根据光的产生理论，腔内的辐射必须与黑体辐射相同。

忽略谐振器发出和吸收的辐射，根据气体的动力学理论，动态平衡要求谐振器（束缚在空间分离点上的电子）的平均动能等于自由移动的气体分子的平均动能。将谐振器的运动分解为三个相互垂直的振荡（在三维空间的运动），我们发现谐振器电子的这种线性振荡的平均能量必须由以下给出：
$$
\bar{E}=\frac{R}{N}T
$$

*   公式（1）：线性振荡的平均能量

其中$R$是气体常数，$N$是每克粒子的物质的量，$T$是绝对温度。由于动能和势能的时间平均值，他认为$\bar{E}$的能量是单个自由气体分子动能的$2/3$。即使某些东西，如辐射过程导致谐振器的平均时间能量偏离$\bar{E}$值，与自由电子和气体分子的碰撞会通过吸收或释放能量将其平均能量返回到$\bar{E}$。因此，只有当每个谐振器都有平均能量$\bar{E}$时，系统才可能存在动态平衡。

在根据统计力学建立了谐振电子的能级之后，我们接着进行了一个类似的考虑，即谐振电子与腔内环境辐射相互作用时能量的变化。他将普朗克方程应用于频率为$v$的谐振器的平均能量：
$$
\bar{E}_\nu=\frac{L^3}{8\pi \nu^2}\rho_\nu=\frac{c^3}{8\pi \nu^2}\rho_\nu
$$

*   公式（2）：频率为$v$的电子共振平均能量

$\bar{E}_v$在这里表示一个本征频率为$v$（每单位频率间隔）的谐振器的平均能量，$L$为光速，这里进行更改使用$c$代替，$v$为频率，$\rho _v$表示腔体的能量密度。

如果在$v$频率共振的电子的净能量不不断增加或减少（违反动态平衡的条件），则必须遵从下列等式：
$$
\frac{R}{N}T=\bar{E}=\bar{E}_\nu=\frac{L^3}{8\pi \nu^2}\rho_\nu=\frac{c^3}{8\pi \nu^2}\rho_\nu
$$

*   公式（3）：共振电子的动态平衡条件

重写后即为：
$$
\rho_\nu=\frac{R}{N}\frac{8\pi \nu^2}{L^3} T
$$

*   公式（4）：瑞利-杰斯定律，给出了能量密度作为频率$v$和温度$T$的函数。

公式（4）为动态平衡的条件，但是公式（4）不仅与实验不一致，还排除了物质与以太之间存在平衡的任何可能性。选择的频率范围越宽，空间中的辐射能量就变得越大，在其极限的情况我们可以得到：

>   "These relations, found to be the conditions of dynamic equilibrium, not only fail to coincide with experiment, but also state that in our model there can be not talk of a definite energy distribution between ether and matter."

$$
\int^\infty_0 \rho_\nu d\nu=\frac{R}{N}\frac{8\pi}{L^3} T \int^\infty_0 \nu^2d\nu=\infty
$$

这无疑灾难性的当头一棒。我们已经证明，1897年的普朗克方程给出了黑体动态平衡的条件，与已知的、经实验验证的给出了正确的电子谐波振荡能量的理论不一致。

## 普朗克基本量子的测定

这里希望说明普朗克关于基本量子的测定在一定程度上是独立于他的黑体辐射理论之外的。

普朗克的黑体辐射方程满足至今所有的实验结果：
$$
\rho_\nu=\frac{\alpha \nu^3}{e^{\frac{\beta \nu}{T}}-1}
$$

*   公式（6）：普朗克黑体辐射方程

这里的$\alpha \approx 6.10 \times 10^{-56}$，$\beta=4.866 \times 10^{-11}$。当$T/v$很大时，也就是说波长很长、辐射密度很高时等式取如下极限：
$$
\rho_\nu=\frac{\alpha}{\beta}\nu^2T
$$
公式（7）与上节中推导的麦克斯韦理论和电子理论一致，使其系数相等：
$$
\frac{R}{N}\frac{8\pi}{L^3}=\frac{\alpha}{\beta} \Rightarrow N=\frac{\beta}{\alpha}\frac{8\pi R}{L^3} \approx 6.17 \times 10^{23}
$$
也就是说，一个氢原子重$1/N \space gram \approx 1.62 \times 10^{-24}g$。这正是普朗克发现的数值，它相应地也和其他方法发现的数值一致。

我们因此得到如下结论：辐射能量密度越高、波长越长，我们一直以来使用的理论基础就越被证明是合理的；但是，它们在短波长和低能量密度的情形下是完全失效的。

>   "We therefore arrive at the conclusion: the greater the energy density and the wavelength of a radiation, the more useful do the theoretical principles we have employed turn out to be: for small wavelengths and small radiation densities, however, these principles fail us completely."

## 辐射的熵

以下的处理主要来自于维恩的研究，爱因斯坦为完整性而呈现出来。

考虑辐射占据了体积$v$。我们假设，当在所有频率上辐射密度$\rho(v)$均被给定时，辐射的可观测属性均被完全确定。由于不同频率的辐射可以被视为是彼此分立同时又不做任何功或转化任何热量的，于是辐射的熵就可以被表示为：
$$
S=v\int_0^\infty \varphi(\rho,\nu)d\nu
$$
这里$\varphi$是变量$\rho$和$\nu$的函数。如果我们声称全反射墙之间的辐射的绝热压缩过程并不与外界交换它的熵，那么我们就可以将$\varphi$简化为一个一元函数。但是，我们并不会去简化它，而是去立即研究函数$\varphi$是如何从黑体辐射定律中得到的。

对于给定能量，$\rho$作为$\nu$的函数能够使熵极大：
$$
\delta\int_0^\infty \varphi(\rho, \nu) d\nu = 0
$$
从此点（极大值点）出发，对每个$\nu$的函数取变分：
$$
\int_0^\infty(\frac{\partial \varphi}{\partial \rho}-\lambda)\delta\rho d\nu=0
$$
这里$\lambda$和$\nu$是独立的，则对于黑体辐射$\frac{\partial \varphi}{\partial \rho}$是独立于$\nu$的。
$$
dS=\frac{\partial \varphi}{\partial \rho}dE
$$
因为$dE$就等于向体系中加入的热量且这一过程是可逆的，我们还有：
$$
dS=\frac{1}{T}dE
$$
则比较可得：
$$
\frac{\partial \varphi}{\partial \rho}=\frac{1}{T}
$$

*   公式（14）：黑体辐射定律

## 单频辐射的熵在低辐射密度下的极限定律

我们的讨论接下来开始修改黑体辐射的理论，这是基于当时的实验结果。我们使用的实验信息是所谓的维恩定律（代替普朗克方程的有效性）。维恩方程可以写成：
$$
\rho=\alpha \nu^3 e^{-\beta \frac{\nu}{T}}
$$

*   公式（15）：维恩指数定律

我们选择维恩定律作为他研究的开始，我们从这个定律中提取了光量子假设，他将维恩状态下的辐射与由（经典）不相互作用的点粒子组成的气体（通常被称为理想玻尔兹曼气体）进行类比。具体地说，他利用了熵对这种气体的体积依赖关系。虽然并非严格有效，但在结果取一定极限时是有效的。

利用对维恩的变换和前一节的关系我们可得：
$$
\varphi(\rho,\nu)=-\frac{\rho}{\beta \nu} \{\ln \frac{\rho}{\alpha \nu^3} -1 \}
$$
假设有能量E，频率在$\nu$和$\nu + d\nu$之间，占据体积$v$的辐射。那么辐射的熵为：
$$
S=v\varphi(\rho,\nu)d\nu=-\frac{E}{\beta \nu} \{\ln \frac{E}{v\alpha \nu^3 d\nu} -1 \}
$$
如果我们限定我们自己去研究这个辐射空间内熵的依存关系，并记在体积为$v_0$时辐射的熵为$S_0$，我们将得到：
$$
S-S_0=\frac{E}{\beta \nu}\ln[\frac{v}{v_0}]
$$


这个等式表明，根据与一团理想气体或一个稀溶液的熵相同的定律，在充分低的密度下，单频辐射的熵随体积而变化。

>   "This equation shows that the entropy of a monochromatic radiation of sufficiently low density varies with the volume in the same manner as the entropy of an ideal gas or a dilute solution."

## 关于气体和稀溶液的熵对体积的依存关系的分子理论研究

这里通过玻尔兹曼原理把熵和概率进行结合，如果讨论一个系统的状态概率是有意义的，更进一步，如果每一次的熵增都能被设想成系统转化到了一个具有更高的概率的状态，那么系统的熵$S_1$就是体系瞬时状态的概率$W_1$的一个函数。因此，如果我们有两个互不影响的系统$S_1$和$S2$，我们可以设：
$$
S_1=\varphi_1(W_1) \\
S_2=\varphi_2(W_2)
$$
最终经过推导，我们可以得到：
$$
S-S_0=\frac{R}{N}\ln W
$$
然后通过计算得到当$n$个粒子全部聚在体积$v_0$中大小为$v$的区域内，同时系统不发生任何其他交换的情况下的概率为：
$$
W=(\frac{v}{v_0})^n
$$
利用玻尔兹曼原理，我们得到：
$$
S-S_0=R(\frac{n}{N})\ln(\frac{v}{v_0})
$$

## 根据玻尔兹曼原理对单频辐射的熵对体积的依存关系表达式的解释

把玻尔兹曼原理所导出的公式（22）和之前单频辐射的熵对体积的依存关系的公式（18）对比，得到如果频率为$\nu$且能量为$E$的单频辐射被（全反射墙）限制在体积$v_0$内，那么在一个随机选择的瞬时全部辐射能量都将在体积$v_0$的某部分$v$中被发现的概率为：
$$
W=(\frac{v}{v_0})^{\frac{N}{R}\frac{E}{\beta \nu}}
$$
我们还想要对比相同温度下黑体辐射的能量子的平均能量值和一个分子的质心平均动能值。后者是$\frac{3}{2}(R/N)T$，而在维恩公式的基础上，我们得到能量子的平均能量值为
$$
\frac{\int_0^\infty \alpha \nu^3 e^{-\frac{\beta \nu}{T}d\nu}}{\int_0^\infty \frac{N}{R\beta \nu}\alpha \nu^3 e^{-\frac{\beta \nu}{T}}d\nu}
$$
如果单频辐射（拥有足够地的密度）是这样行为的，它的熵符合我们所考虑的对体积的依存关系，它本身是由能量量级为$R\beta\nu/N$的能量子构成的非连续媒介，那么去研究当光由这样的能量子构成时支配光的产生与转化的定律是否同样成立就显得合理了。

## 斯托克斯规则

由单频光激发光转化为多频光，不论通过哪种中介过程，出现的最终结果都是没有区别的。如果光激发光的物质不能够被视为一个永久的能源，那么，根据能量守恒定律，被发射的能量子的能量不能够比产生它的光子的能量要大；因此就有：
$$
\frac{R}{N}\beta\nu_2 \leq \frac{R}{N}\beta\nu_1
$$
这就是著名的Stokes规则。

需要强调的是，根据我们的设想，在低照度的情况下，发射光的强度必须和入射光的强度成比例，因为每一个入射能量子都将引发一个如上所述的基本过程，并且和其他入射能量子相互独立。特别地，不存在这样更低的入射光强度的极限，在它之下光将无法激发荧光效应。

根据针对这里展示的现象的设想，Stokes规则在以下情况下出现例外是可能的：

例外：

1.  若每单位体积同时被转化生成的能量子数量极大，以至于发射光的一个能量子可以从很多入射能量子中吸收能量。
2.  当在Wien定律适用范围内，入射（或发射）光并不具有和黑体辐射相同的能量分布；若，举个例子，入射光是由一个温度那样高的物体产生的，以至于Wien定律不再适用于与之相关的波长。

后一种可能情况需要特殊关注。根据上述构建的设想，在Wien定律适用范围内，若我们考虑辐射的能量，甚至处于密度很低的“非Wien辐射”也将有不同于黑体辐射的行为——这确实是可能的。

## 由固体照明产生的阴极射线

光电效应就不需要过多的解释了，爱因斯坦给出了详细推导，结果为：
$$
E=hv-P
$$
其中，$h$是普朗克常数，$v$是辐射频率，$P$是从物体表面逃逸所需的能量。爱因斯坦指出，公式（26）解释了莱纳德1902年的观察结果，即电子能量“丝毫不依赖于光强度”。这个等式同样值得注意，因为它做出了非常强有力的预测：

-   首先，它表明单个射出电子的能量随光的频率线性增加；
-   第二，它表明$(E,v)$图的斜率是一个常数，与被辐照材料的性质无关；
-   第三，它表明$(E,v)$图的斜率的值被预测为普朗克常数，由辐射定律决定。

换句话说，爱因斯坦在他的论文中提出，每个光量子的能量等于光的频率乘以一个由辐射定律决定的常数，这个常数现在被称为普朗克常数h。

他的预测解释了光源的能量势能只取决于光的频率而不是光的强度：

-   低强度、高频率的光源可以提供少量产生光电效应的高能光子，而
-   一个高强度、低频率的光源不能提供足够的单独能量来“驱逐”任何电子的光子。

## 紫外光导致的气体电离

这一部分类比于光电效应，就不过多赘述。

## 参考文献

[1] A. Einstein. Concerning an Heuristic Point of View Toward the Emission and Transformation of Light. American Journal of Physics, v. 33, n. 5

