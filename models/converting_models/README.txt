CONVERTING PKL MODELS TO JS OBJECTS:
**** if converting is needed must use this modified environment because the convert libraries have been changed during the years 
we must to use python 3.7 + the modified sklearn_porter library in new sterilic envionment
requirements:
need to download this versions only !!!
versions:
pip install scikit-learn==0.22.2.post1
pip install sklearn-porter==0.7.4
pip install joblib==1.3.2


C:\\....\porter_env\Lib\site-packages\sklearn_porter\estimator\classifier\RandomForestClassifier
have to use my __init__.py in  the RandomForestClassifier folder
delete all the old syntax 
like:
from sklearn.tree.tree import DecisionTreeClassifier ------------------->> from sklearn.tree import DecisionTreeClassifier

change this :
self.n_features = est.estimators_[0].n_features_ ---------------->>>self.n_features = est.estimators_[0].n_features_in_





c:\\........\sklearn_porter\__init__.py:
change 
meta = load(f, encoding='utf-8')------------------->>meta = load(f)



<path-to-your-project>\.venv\Lib\site-packages\sklearn_porter\Porter.py

from sklearn.neural_network.multilayer_perceptron \--------------------------->>from sklearn.neural_network import MLPClassifier
from sklearn.tree.tree import DecisionTreeClassifier-------------------------->>from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble.weight_boosting import AdaBoostClassifier---------------->>from sklearn.ensemble import AdaBoostClassifier 
etc   we just need to change the format to the new one 



Lib\site-packages\sklearn_porter\Porter.py

error = "Currently the given model '{algorithm_name}' is not supported."
raise ValueError(error.format(**locals()))
----->>>
error = f"Currently the given model '{type(model).__name__}' is not supported."
raise ValueError(error)


except ImportError:
    error = "Currently the given model '{algorithm_name}' " \
            "isn't supported.".format(**self.__dict__)
    raise AttributeError(error)
--------------->>
except ImportError:
    error = "Currently the given model '{estimator_name}' isn't supported.".format(**self.__dict__)
    raise AttributeError(error)

error = "Currently the given model '{algorithm_name}' isn't supported.".format(**self.__dict__)
--------->>>error = f"Currently the given model '{self.estimator_name}' isn't supported."





.venv\Lib\site-packages\sklearn_porter\estimator\classifier\RandomForestClassifier\__init__.py

need to comment this section:
if not isinstance(estimator.base_estimator, DecisionTreeClassifier):
    msg = "The classifier doesn't support the given base estimator %s."
    raise ValueError(msg, estimator.base_estimator)




