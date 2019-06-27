<template>
    <div>
        <!--<rotate-buttom :hasIcon="true" iconClass="el-icon-arrow-down el-icon--right">旋转吧箭头</rotate-buttom>-->
        <div style="position:relative;">
            <div style="position:absolute;left:50%;top:50%;margin-top:96px;width:264px;height:192px;">
                居中测试
            </div>
        </div>
    </div>
</template>

<script>
import RotateButtomComponent from "./composents/rotatebuttom.vue"

export default {
    data(){
        return {
            
        }
    },
    components:{
        rotateButtom: RotateButtomComponent
    }
}
</script>